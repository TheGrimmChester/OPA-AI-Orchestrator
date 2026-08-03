# Install

## Laptop smoke

```bash
docker build -t ora-api:smoke .
docker run --rm -p 8091:8091 ora-api:smoke
```

## Production / NAS

Deploy `ora-api:nas` only. Never run `*:smoke` on production hosts.
