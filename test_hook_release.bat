call build_release.bat
pushd target\i686-pc-windows-msvc\release\
test_launcher.exe
popd
