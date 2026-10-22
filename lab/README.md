# SSH test target

Throwaway container that runs the vulnerable PHP release 8.3.35 with an SSH
server, so the `ssh` mode of php2shell-scanner can be tested end to end.

```bash
# 1. a key pair for the scanner to authenticate with
ssh-keygen -t ed25519 -f ./id_ed25519 -N ''

# 2. hand the public key to the container
cp ./id_ed25519.pub ./authorized_keys

# 3. start it
docker compose up -d --build

# 4. scan it
../php2shell-scanner ssh \
  -H 127.0.0.1 -p 2222 -U root \
  -i ./id_ed25519 \
  --known-hosts ./known_hosts \
  --webroot /var/www/html
```

The first connection is refused unless `known_hosts` already holds the host
key. Fill it once:

```bash
ssh-keyscan -p 2222 127.0.0.1 >> ./known_hosts
```

For a throwaway lab you can skip the host key check with
`--insecure-host-key`.

The fixture also accepts a password for root (`labpass123` by default, change it
with `P2S_ROOT_PASSWORD`) so the password path can be tested:

```bash
../php2shell-scanner ssh -H 127.0.0.1 -p 2222 -U root --password labpass123
```

Stop it again:

```bash
docker compose down
```
