# Adversarial ML Defense - Practical Examples

## Quick Start

### Example 1: Basic Setup with Adversarial Defense

The simplest way to enable ML evasion:

```bash
# Server side (no changes needed)
wstunnel server wss://0.0.0.0:443

# Client side with adversarial ML defense
wstunnel client \
  --adversarial-ml-defense \
  -L tcp://8080:google.com:443 \
  wss://your-server.com
```

This enables:
- Directional padding (small packets made larger)
- Moderate IAT randomization (50%)
- No overhead from dummy packets

**Use case**: General purpose ML evasion with minimal overhead.

---

## Real-World Scenarios

### Scenario 1: Bypassing the Great Firewall (GFW)

The GFW uses ML classifiers to detect VPN and tunnel traffic. Here's a configuration that works well:

```bash
# Client configuration for GFW evasion
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.7 \
  --traffic-profile chrome-browsing \
  --tls-sni-override cloudflare.com \
  --http-headers "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -L socks5://127.0.0.1:1080 \
  wss://your-server.com/v1

# Use with curl
curl -x socks5://localhost:1080 https://www.google.com

# Use with Firefox
# Set SOCKS5 proxy to localhost:1080 in Firefox settings
```

**Why this works:**
- `adaptive` padding changes strategy based on traffic patterns
- `0.7` IAT randomization adds significant timing variation
- `chrome-browsing` profile makes traffic look like Chrome WebSocket
- SNI override hides the real destination
- Custom User-Agent mimics real browser

---

### Scenario 2: SSH Tunneling Through DPI

SSH traffic is heavily fingerprinted by DPI systems. Protect it with:

```bash
# Start wstunnel client with ML defense
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy directional \
  --adversarial-iat-randomization 0.6 \
  -L tcp://2222:target-server.com:22 \
  wss://tunnel-server.com

# Connect via SSH through the tunnel
ssh -p 2222 user@localhost

# Or use ProxyCommand for seamless SSH
# Add to ~/.ssh/config:
# Host target-server
#   ProxyCommand nc -X connect -x localhost:2222 %h %p
#   User youruser
```

**Why this works:**
- SSH traffic gets wrapped in WebSocket with adversarial patterns
- DPI sees variable-sized WebSocket frames, not SSH patterns
- IAT randomization breaks SSH timing fingerprints
- SSH data remains unmodified (binary protocol safe)

---

### Scenario 3: HTTPS Browsing Through HTTP Proxy

If you're behind a corporate proxy that inspects traffic:

```bash
# Forward through corporate HTTP proxy with ML evasion
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.5 \
  --http-proxy corporate-proxy.company.com:8080 \
  --http-proxy-login youruser \
  --http-proxy-password yourpass \
  --traffic-profile chrome-browsing \
  -L http://127.0.0.1:8888 \
  wss://external-server.com

# Configure browser to use localhost:8888 as HTTP proxy
```

**Why this works:**
- Adversarial ML makes tunnel traffic look like legitimate WebSocket
- `chrome-browsing` profile mimics real Chrome browser patterns
- Corporate proxy sees normal-looking HTTPS (WebSocket upgrade)
- Internal inspection sees realistic packet patterns

---

### Scenario 4: Maximum Stealth (High-Risk Environment)

When you need maximum evasion and can tolerate overhead:

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.9 \
  --adversarial-dummy-packets \
  --adversarial-dummy-packet-rate 10.0 \
  --traffic-profile chrome-browsing \
  --websocket-ping-frequency 25s \
  --http-headers "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --http-headers "Accept-Language: en-US,en;q=0.9" \
  --http-headers "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -L socks5://127.0.0.1:1080 \
  wss://tunnel-server.com
```

**Trade-offs:**
- ✅ Maximum ML evasion
- ✅ Very realistic traffic patterns
- ❌ ~40-60% bandwidth overhead (dummy packets)
- ❌ +50-100ms latency (aggressive IAT randomization)
- ❌ Not suitable for real-time applications (VoIP, gaming)

**Best for**: High-risk environments where detection = blocking

---

### Scenario 5: Custom Traffic Profile (Advanced)

Create a custom profile from real application traffic:

```bash
# Step 1: Capture real traffic (do this from an unblocked network)
# Capture Zoom call for 1 minute
tcpdump -i any 'host zoom.us and port 443' -w zoom-meeting.pcap -c 10000

# Step 2: Build wstunnel with PCAP learning support
cd wstunnel
cargo build --release --features pcap-learning

# Step 3: Use custom profile
./target/release/wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --traffic-profile zoom-meeting.pcap \
  -L tcp://8080:actual-destination.com:443 \
  wss://tunnel-server.com

# Your tunnel now looks like Zoom traffic!
```

**Custom profiles for common apps:**

```bash
# Capture different application patterns

# Discord voice chat
tcpdump -i any 'host discord.gg and port 443' -w discord.pcap -c 5000

# Netflix streaming  
tcpdump -i any 'host netflix.com and port 443' -w netflix.pcap -c 20000

# WhatsApp call
tcpdump -i any 'host whatsapp.com and port 443' -w whatsapp.pcap -c 8000

# Use any of these with wstunnel:
wstunnel client \
  --adversarial-ml-defense \
  --traffic-profile discord.pcap \
  -L ... wss://...
```

---

## Performance Tuning

### Low Latency (Gaming, VoIP)

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy directional \
  --adversarial-iat-randomization 0.3 \
  -L ... wss://...
```
- Minimal IAT randomization (only +5-15ms)
- Efficient directional padding
- No dummy packets

### High Throughput (File Transfers, Streaming)

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy directional \
  --adversarial-iat-randomization 0.4 \
  -L ... wss://...
```
- Low overhead padding
- Moderate randomization
- Focuses on efficient large transfers

### Balanced (General Use)

```bash
wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.5 \
  -L ... wss://...
```
- Default settings
- Good balance of stealth and performance

---

## Combining with Other Evasion Techniques

### Full Stealth Stack

Combine adversarial ML with other wstunnel features:

```bash
wstunnel client \
  # Adversarial ML
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.7 \
  --traffic-profile chrome-browsing \
  \
  # TLS/SNI evasion
  --tls-sni-override cloudflare.com \
  --tls-verify-certificate \
  \
  # HTTP header mimicking
  --http-headers "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --http-headers "Accept-Language: en-US,en;q=0.9" \
  --http-headers "Referer: https://www.google.com/" \
  \
  # WebSocket masking
  --websocket-mask-frame \
  --websocket-ping-frequency 30s \
  \
  # Tunnel configuration
  -L socks5://127.0.0.1:1080 \
  wss://tunnel-server.com/random-path-$RANDOM
```

---

## Testing Your Configuration

### Check If Adversarial Defense Is Active

```bash
# Enable debug logging
export RUST_LOG=debug

wstunnel client --adversarial-ml-defense -L ... wss://...

# Look for log messages:
# - "Adversarial ML defense enabled"
# - "Applied adversarial padding: X bytes"
# - "IAT randomization: X ms"
```

### Measure Overhead

```bash
# Without adversarial defense
time curl -x socks5://localhost:1080 https://example.com/large-file

# With adversarial defense
time curl -x socks5://localhost:1080 https://example.com/large-file

# Compare bandwidth and latency
```

### Verify Packet Patterns

```bash
# Capture tunnel traffic
tcpdump -i any 'host tunnel-server.com and port 443' -w tunnel.pcap

# Analyze with Wireshark
# Look for:
# - Variable packet sizes (not uniform)
# - Variable inter-arrival times (not constant)
# - Realistic size distribution
```

---

## Troubleshooting

### High Latency

**Problem**: Connection is too slow

**Solution**: Reduce IAT randomization
```bash
--adversarial-iat-randomization 0.3  # Lower value
```

### High Bandwidth Usage

**Problem**: Too much data being sent

**Solution**: 
1. Disable dummy packets (if enabled)
2. Use directional padding instead of adaptive
```bash
--adversarial-padding-strategy directional  # More efficient
# Remove --adversarial-dummy-packets
```

### Still Getting Blocked

**Problem**: DPI still detects the tunnel

**Solutions**:
1. Try different traffic profile:
```bash
--traffic-profile webrtc-video  # Different pattern
```

2. Increase randomization:
```bash
--adversarial-iat-randomization 0.9  # More aggressive
```

3. Enable dummy packets:
```bash
--adversarial-dummy-packets \
--adversarial-dummy-packet-rate 15.0
```

4. Combine with domain fronting:
```bash
--tls-sni-override popular-domain.com
```

---

## Integration Examples

### Docker Compose

```yaml
version: '3'
services:
  wstunnel-client:
    image: wstunnel:latest
    command: >
      client
      --adversarial-ml-defense
      --adversarial-padding-strategy adaptive
      --adversarial-iat-randomization 0.6
      --traffic-profile chrome-browsing
      -L socks5://0.0.0.0:1080
      wss://tunnel-server.com
    ports:
      - "1080:1080"
    restart: unless-stopped
```

### Systemd Service

```ini
[Unit]
Description=Wstunnel Client with Adversarial ML Defense
After=network.target

[Service]
Type=simple
User=wstunnel
ExecStart=/usr/local/bin/wstunnel client \
  --adversarial-ml-defense \
  --adversarial-padding-strategy adaptive \
  --adversarial-iat-randomization 0.6 \
  -L socks5://127.0.0.1:1080 \
  wss://tunnel-server.com
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wstunnel-client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wstunnel-client
  template:
    metadata:
      labels:
        app: wstunnel-client
    spec:
      containers:
      - name: wstunnel
        image: wstunnel:latest
        args:
        - client
        - --adversarial-ml-defense
        - --adversarial-padding-strategy=adaptive
        - --adversarial-iat-randomization=0.6
        - --traffic-profile=chrome-browsing
        - -L
        - socks5://0.0.0.0:1080
        - wss://tunnel-server.com
        ports:
        - containerPort: 1080
```

---

## Best Practices

### ✅ Do

- **Start with defaults** and adjust based on results
- **Monitor performance** to find optimal settings
- **Test thoroughly** before relying on tunnel
- **Combine techniques** for maximum evasion
- **Keep server updated** to latest wstunnel version

### ❌ Don't

- **Don't over-optimize** if basic settings work
- **Don't use maximum settings** unless necessary (overhead!)
- **Don't forget to test** with real applications
- **Don't expose tunnel ports** to public internet
- **Don't use predictable** SNI/paths/headers

---

## Security Notes

1. **Adversarial ML is not perfect**: Advanced ML models may still detect patterns
2. **Active probing**: This doesn't protect against active probing attacks
3. **Traffic analysis**: Total volume and timing can still leak information
4. **Use with other defenses**: Combine with domain fronting, TLS, etc.
5. **Regular updates**: ML detection evolves, keep wstunnel updated

---

## Additional Resources

- [Main Documentation](./adversarial_ml_defense.md) - Detailed technical information
- [Academic References](./adversarial_ml_defense.md#academic-references) - Research papers
- [Performance Impact](./adversarial_ml_defense.md#performance-impact) - Overhead analysis
- [GitHub Issues](https://github.com/erebe/wstunnel/issues) - Report bugs or ask questions

