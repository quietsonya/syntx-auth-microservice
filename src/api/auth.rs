use jsonwebtoken::{encode, Header, EncodingKey};
use tonic::{Request, Response, Status, transport::Channel};
use rand::random;
use redis::{Commands};
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
        users_service_client::UsersServiceClient
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
    pub users_service_client: UsersServiceClient<Channel>
}

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

        let user = self.users_service_client
            .to_owned()
            .create_user(CreateUserRequest {
                email: String::from(&dto.email),
                username: String::from(&dto.username),
                password: password_hash,
                salt: salt.to_string()
            })
            .await
            .unwrap();

        let now_timestamp = Utc::now().timestamp();
        
        let payload = TokenPayload {
            id: String::from(&user.get_ref().id),
            email: String::from(&dto.email),
            exp: now_timestamp as usize,
        };

        let access_token: String = encode(
            &Header::default(),
            &payload,
            &EncodingKey::from_secret("secret".as_ref())
        ).unwrap();

        let refresh_token: String = access_token[0..6].to_owned() + &random::<i32>().to_string();

        let expires_in = Option::from(Timestamp {
            seconds: now_timestamp,
            nanos: 0
        });

        let _: String = self.redis_client
            .get_connection()
            .unwrap()
            .set("s", "value")
            .unwrap();

        let response = Tokens {
            access_token,
            refresh_token,
            expires_in,
        };
        Ok(Response::new(response))
    }

    async fn login(
        &self,
        _request: Request<LoginRequest>,
    ) -> Result<Response<Tokens>, Status> {
        let timestamp = Timestamp {
            seconds: 123123123,
            nanos: 123123123 * 1000
        };
        let response = Tokens {
            access_token: String::from("asd"),
            refresh_token: String::from("asd"),
            expires_in: Option::from(timestamp),
        };
        Ok(Response::new(response))
    }

    async fn refresh(
        &self,
        _request: Request<RefreshTokensRequest>,
    ) -> Result<Response<Tokens>, Status> {
        let timestamp = Timestamp {
            seconds: 123123123,
            nanos: 123123123 * 1000
        };
        let response = Tokens {
            access_token: String::from("asd"),
            refresh_token: String::from("asd"),
            expires_in: Option::from(timestamp),
        };
        Ok(Response::new(response))
    }

    async fn logout(
        &self,
        _request: Request<LogoutRequest>,
    ) -> Result<Response<Success>, Status> {
        Ok(Response::new(Success {}))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenPayload {
    id: String,
    email: String,
    exp: usize,
}
