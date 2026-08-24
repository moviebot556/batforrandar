# Bitcoin Key Scanner (Render Free Tier & Railway Optimized)

High-performance, **zero-allocation** Bitcoin Private Key Scanner & Matcher accelerated with **Montgomery Batch Elliptic Curve Math**. Engineered specifically to run 24/7 on **Render (Free Tier: 0.1 CPU, 512MB RAM)** and **Railway.com (<1.9 vCPU)** while consuming **<20MB RAM** and **0 B/op** heap allocations.

---

## ⚡ Key Highlights & Optimizations

- **Montgomery Batch Inversion (256 Points/Batch)**:
  - Replaces slow scalar multiplication ($k \cdot G$, ~13,000 ns) with Jacobian consecutive point additions ($P_{j+1} = P_j + G$, ~150 ns) and batch modular inversion of all $Z$-coordinates with a single inversion.
  - Achieves **~700,000+ keys/sec per core** with **0 heap allocations (0 B/op)**.
- **Render Free Tier Optimized (0.1 CPU / 512MB RAM)**:
  - Defaults to `WORKERS=1` and `GOMAXPROCS=1` for single-thread efficiency on throttled 0.1 CPU environments.
  - Cooperative CPU yielding (`runtime.Gosched()`) guarantees `/health` and web dashboard remain immediately responsive.
- **Ultra-Low Memory (<20MB RAM)**:
  - Target addresses are loaded into a compact zero-value hash map (`map[[20]byte]struct{}`), eliminating string pointer overhead (~1.3MB for 33,000+ addresses).
  - Go memory ceiling strictly enforced via `debug.SetMemoryLimit(128MB)` and `debug.SetGCPercent(20)` (well below Render's 512MB limit).
- **Real-Time Live Web Dashboard**:
  - Dark-mode web interface displaying live keys/sec, total scanned keys, RAM usage, active vCPU limit, Telegram alert status, and found matches.
- **Instant Telegram Notifications**:
  - Automated instant alerts with Target Address, Hex Private Key, Decimal, and WIF format.
- **Flexible Modes**:
  - **Full 256-bit Random Mode**: Cryptographically secure 256-bit random keyspace scanning.
  - **Puzzle Bit Range Mode (`PUZZLE_BITS`)**: Optimized bounded range scanning (e.g. Puzzle #66: $2^{65}$ to $2^{66}-1$).
  - **Custom Hex Range Mode (`KEY_RANGE_MIN` / `KEY_RANGE_MAX`)**: Custom range scanning.

---

## 🛠️ How to Deploy on Render.com (Free Tier)

1. Log into **[dashboard.render.com](https://dashboard.render.com)**.
2. Click **New +** -> **Web Service**.
3. Connect your GitHub repository (`batforrandar`).
4. Select **Docker** environment and **Free** tier.
5. In **Environment Variables**:
   - `PORT`: `8080`
   - `WORKERS`: `1` (Optimal for 0.1 CPU Free Tier)
   - `MAX_VCPU`: `0.1`
   - `PUZZLE_BITS`: `66` (Optional)
   - `TELEGRAM_BOT_TOKEN`: `<your_bot_token>` (Optional)
   - `TELEGRAM_CHAT_ID`: `<your_chat_id>` (Optional)
6. Under **Advanced Settings**, set **Health Check Path** to `/health`.
7. Click **Create Web Service**.

---

## 🛠️ How to Deploy on Railway.com

1. Push this project to your GitHub repository.
2. Go to [Railway.com](https://railway.com) -> Click **"+ New Project"** -> **"Deploy from GitHub repo"**.
3. In **Variables**: Set `MAX_VCPU=1.9`, `WORKERS=2`.

---

## 🌐 Endpoints

- `/` : Live Dark-Mode Web Dashboard.
- `/health` : JSON Healthcheck (`{"status":"healthy","uptime":...}`).
- `/stats` : Live metrics JSON API.
