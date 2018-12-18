Heavily based on https://github.com/yinghuocho/gotun2socks

This library supports TCP and UDP traffic on a TUN device. No other protocols
are currently supported.

gotun is primarily intended for use in VPNs, where the TUN device represents the
vpn endpoint and functions as a router.

### UDP
UDP traffic is sent directly to/from the remote address without use of a proxy.

### TCP
TCP traffic can be proxied by plugging into ...
