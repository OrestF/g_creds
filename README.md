# GCreds

Read, encrypt and decrypt your .env files.

## Run

## Usage

There are 3 main actions `show`, `encrypt`, `decrypt`.

### Read
encrypted credentails `.env.production.enc`

```shell
go run main.go -action=show -environment=production
```

### Decrypt
encrypted credentials `.env.production.enc` into `.env.production`

```shell
go run main.go -action=decrypt -environment=production
```

Edit `.env.production` up to your needs

### Encrypt

`.env.production` into `.env.production.enc`

You could use as many environemnts as you need. Just make sure file name and flag are same `-environment=whatever` == `.env.whatever`

