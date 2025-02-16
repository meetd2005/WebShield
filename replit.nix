{pkgs}: {
  deps = [
    pkgs.nmap
    pkgs.rustc
    pkgs.libiconv
    pkgs.cargo
    pkgs.postgresql
    pkgs.openssl
  ];
}
