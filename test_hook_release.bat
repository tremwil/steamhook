call build_release.bat
pushd target\i686-pc-windows-msvc\debug\
test_launcher.exe
popd