# Rollback

## Goal
Restore Hermes traffic to Headroom directly and remove privacy-gateway from the active request path with minimal blast radius.

## Researcher canary rollback

```bash
systemctl --user stop hermes-gateway-researcher.service
rm -f ~/.config/systemd/user/hermes-gateway-researcher.service.d/zz-privacy-gateway.conf
systemctl --user daemon-reload
systemctl --user start hermes-gateway-researcher.service
```

## Default profile rollback

```bash
sudo systemctl stop hermes-gateway.service
sudo rm -f /etc/systemd/system/hermes-gateway.service.d/zz-privacy-gateway.conf
sudo systemctl daemon-reload
sudo systemctl start hermes-gateway.service
```

## Full service rollback

```bash
sudo systemctl disable --now privacy-gateway.service
sudo rm -f /etc/systemd/system/privacy-gateway.service
sudo systemctl daemon-reload
```

## Post-rollback verification

1. Confirm Hermes profile env points back to Headroom:
   - `http://127.0.0.1:18787/v1`
2. Confirm `headroom-proxy.service` is active.
3. Run a one-shot Hermes CLI request on the affected profile.
4. Check Headroom `/stats` for `/v1/responses` traffic.
