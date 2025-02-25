{pkgs}: {
  deps = [
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libxcrypt
    pkgs.rustc
    pkgs.libiconv
    pkgs.cargo
  ];
}
