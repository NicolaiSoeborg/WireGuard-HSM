module golang.zx2c4.com/wireguard

go 1.24

toolchain go1.24.2

require (
	github.com/garnoth/pkclient v0.0.0
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
	golang.org/x/sys v0.33.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20220817001344-846276b3dbc5
)

require (
	github.com/google/btree v1.0.1 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
)

require (
	github.com/miekg/pkcs11 v1.1.2-0.20231115102856-9078ad6b9d4b // indirect
	golang.org/x/term v0.32.0 // indirect
)

replace github.com/garnoth/pkclient => ../pkclient
