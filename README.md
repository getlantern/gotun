TUN implementation based on https://github.com/yinghuocho/gotun2socks

This library supports TUN devices on Windows, Darwin and Linux.

gotun is primarily intended for use in VPNs, where the TUN device represents the
vpn endpoint and functions as a router.

Unlike the original gotun2socks, this does not include the actual routing
capability, just the raw TUN device.
