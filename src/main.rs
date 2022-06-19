mod api;

use tonic::transport::{Server, Channel};
use api::auth::AuthController;
use redis::Client;
use proto::{auth::auth_service_server::AuthServiceServer, users::users_service_client::UsersServiceClient};


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "127.0.0.1:50052".parse().unwrap();
    let redis_client = Client::open("redis://127.0.0.1:6379/1")?;
    let users_service_client: UsersServiceClient<Channel> = UsersServiceClient::connect(
        "http://127.0.0.1:50051"
    ).await?;
    let auth_controller = AuthController { 
        redis_client,
        users_service_client
    };
    let auth_service_server = AuthServiceServer::new(auth_controller);

    println!("Auth service listening on {}", url);
    Server::builder()
        .add_service(auth_service_server)
        .serve(url)
        .await?;

    Ok(())
}