# DirectDNS

Allow IPv6 prefixed domain zones to be directly forwarded to that IPv6 address.

This enables zero trust DNS zones and resolving for those running a DirectDNS resolver locally.

Can be used with non-global network addresses, such as [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go). Enables direct Yggdrasil DNS lookup for clients running Yggdrasil + DirectDNS, while also allowing non-Yggdrasil clients to access the same services through a public proxy.

## Example Usage

```
. {
    directdns yggdrasil.trustless.cloud
    forward . 1.1.1.1
}
```
