fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("./proto/auth/auth.proto")?;
    tonic_build::compile_protos("./proto/users/users.proto")?;
    Ok(())
}