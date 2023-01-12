cargo build --target i686-pc-windows-msvc --release --all
cargo build --target x86_64-pc-windows-msvc --release --all

cargo test --target i686-pc-windows-msvc --release --all
cargo test --target x86_64-pc-windows-msvc --release --all

copy third_party\steamworks_bin\steam_api.dll target\i686-pc-windows-msvc\release\
copy third_party\steamworks_bin\steam_api64.dll target\x86_64-pc-windows-msvc\release\