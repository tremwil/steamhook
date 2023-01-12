cargo build --target i686-pc-windows-msvc --all
cargo test --target i686-pc-windows-msvc --all

cargo build --target x86_64-pc-windows-msvc --all
cargo test --target x86_64-pc-windows-msvc --all

copy third_party\steamworks_bin\steam_api.dll target\i686-pc-windows-msvc\debug\
copy third_party\steamworks_bin\steam_api64.dll target\x86_64-pc-windows-msvc\debug\