use jsonwebtoken::{
    encode,
    decode,
    Header,
    EncodingKey,
    Validation,
    Algorithm,
    DecodingKey,
    TokenData,
    errors::Error,
};
use tonic::{Request, Response, Status, transport::Channel};
use redis::{Commands, Client, RedisError, RedisResult, Value};
use proto::{
    auth::{
        LoginRequest,
        LogoutRequest,
        RefreshTokensRequest,
        RegisterRequest,
        Success,
        Tokens,
        auth_service_server::AuthService,
    },
    users::{
        CreateUserRequest,
        users_service_client::UsersServiceClient,
        UserByEmailRequest,
        UserByIdRequest,
    }
};
use chrono::offset::Utc;
use prost_types::Timestamp;
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher,
        SaltString
    },
    Pbkdf2
};
use serde::{Serialize, Deserialize};
#[derive(Debug)]
pub struct AuthController {
    pub redis_client: redis::Client,
    pub users_service_client: UsersServiceClient<Channel>,
}

const ACCESS_SECRET: &[u8; 13] = b"access_secret";
const REFRESH_SECRET: &[u8; 14] = b"refresh_secret";

#[tonic::async_trait]
impl AuthService for AuthController {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<Tokens>, Status> {
        let dto = request.get_ref();
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = Pbkdf2
            .hash_password(dto.password.as_bytes(), &salt)
            .unwrap()
            .hash
            .unwrap()
            .to_string();

        let user = match self.users_service_client
            .to_owned()
            .create_user(CreateUserRequest {
                email: String::from(&dto.email),
                username: String::from(&dto.username),
                password: password_hash,
                salt: salt.to_string()
            })
            .await {
                Ok(usr) => usr,
                Err(e) => panic!("Users service connection failed. Error: {}", e),
            }.get_ref().to_owned();

        let response: Tokens = generate_tokens(user.id, user.email, &self.redis_client)?;

        Ok(Response::new(response))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<Tokens>, Status> {
        let dto = request.get_ref();

        let user = match self.users_service_client
            .to_owned()
            .get_user_by_email(UserByEmailRequest {
                email: String::from(&dto.email)
            })
            .await {
                Ok(usr) => usr,
                Err(e) => panic!("Users service connection failed. Error: {}", e),
            }.get_ref().to_owned();

        if user.password != Pbkdf2
            .hash_password(dto.password.as_bytes(), &user.salt)
            .unwrap()
            .hash
            .unwrap()
            .to_string() {
            return Err(Status::unauthenticated("Wrong password"))
        }
        
        let response: Tokens = generate_tokens(user.id, user.email, &self.redis_client)?;
        
        Ok(Response::new(response))
    }

    async fn refresh(
        &self,
        request: Request<RefreshTokensRequest>,
    ) -> Result<Response<Tokens>, Status> {

        let refresh_token_from_store: String;

        let user_id: String;

        let refresh_token_from_request_payload: Result<TokenData<RefreshTokenPayload>, Error> = decode(
            &request.get_ref().refresh_token,
            &DecodingKey::from_secret(REFRESH_SECRET),
            &Validation::new(Algorithm::HS256)
        );




        match refresh_token_from_request_payload {
            Ok(payload) => user_id = payload.claims.id,
            Err(_) => return Err(Status::unauthenticated("Invalid refresh token")),
        }

        match self.redis_client.get_connection() {
            Ok(mut connection) => {
                let refresh_token: &Result<String, RedisError> = &connection.get(&user_id);

                match refresh_token {
                    Ok(refresh_token) => refresh_token_from_store = refresh_token.to_owned(),
                    Err(_) => return Err(Status::unauthenticated("Wrong refresh token"))
                };
            },
            Err(e) => return Err(Status::unavailable(
                String::from("Redis connection error") + &e.to_string()
            )),
        };

        if request.get_ref().refresh_token != refresh_token_from_store {
            return Err(Status::unauthenticated("Wrong refresh token"))
        }

        let user = match self.users_service_client
        .to_owned()
        .get_user_by_id(UserByIdRequest {
            user_id
        })
        .await {
            Ok(usr) => usr,
            Err(e) => panic!("Users service connection failed. Error: {}", e),
        }.get_ref().to_owned();

        let response: Tokens = generate_tokens(
            user.id,
            user.email,
            &self.redis_client
        )?;

        Ok(Response::new(response))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<Success>, Status> {

        let access_token_from_request: TokenData<AccessTokenPayload>;
        match decode(
            &request.get_ref().access_token,
            &DecodingKey::from_secret(ACCESS_SECRET),
            &Validation::new(Algorithm::HS256)
        ) {
            Ok(access_token) => access_token_from_request = access_token,
            Err(_) => return Err(Status::unauthenticated("Wrong access token")),
        };

        match self.redis_client.get_connection() {
            Ok(mut connection) => {
                let _: &RedisResult<Value> = &connection
                    .del(access_token_from_request.claims.id);
                return Ok(Response::new(Success {}))
            },
            Err(e) => return Err(Status::unavailable(
                String::from("Redis connection error") + &e.to_string()
            )),
        };
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenPayload {
    id: String,
    email: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshTokenPayload {
    id: String,
    exp: usize,
}

fn generate_tokens(id: String, email: String, redis_client: &Client) -> Result<Tokens, Status> {

    let now_timestamp = Utc::now().timestamp();

    let access_token_payload = AccessTokenPayload {
        id: String::from(&id),
        email: String::from(&email),
        exp: (now_timestamp + 600) as usize, // 10 mins
    };
        
    let refresh_token_payload = RefreshTokenPayload {
        id: String::from(&id),
        exp: (now_timestamp + 2592000) as usize, // 30 days
    };

    let access_token: String = encode(
        &Header::new(Algorithm::HS256),
        &access_token_payload,
        &EncodingKey::from_secret(ACCESS_SECRET)
    ).unwrap();

    let refresh_token: String = encode(
        &Header::new(Algorithm::HS256),
        &refresh_token_payload,
        &EncodingKey::from_secret(REFRESH_SECRET)
    ).unwrap();

    let expires_in = Option::from(Timestamp {
        seconds: now_timestamp + 600,
        nanos: 0
    });

    let redis_connection = redis_client.get_connection();

    match redis_connection {
        Ok(mut redis_connection) => {
            let refresh_token_in_store: Result<String, RedisError> = redis_connection
                .set(&id, &refresh_token);
            
                match refresh_token_in_store {
                    Ok(_) => Ok(Tokens {
                        access_token,
                        refresh_token,
                        expires_in
                    }),
                    Err(e) => Err(Status::aborted(
                        String::from("Set value redis error") + &e.to_string()
                    )),
                }
        },
        Err(e) => Err(Status::unavailable(
            String::from("Redis connection error") + &e.to_string()
        )),
    }

}
