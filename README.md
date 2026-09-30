# NEXTAPK (Netlify)
1. `npm install`
2. `npm run hash -- 'your-long-password'` → prints ADMIN_PASSWORD_HASH and SESSION_SECRET.
3. In Netlify → Site settings → Environment variables set: ADMIN_EMAIL, ADMIN_PASSWORD_HASH, SESSION_SECRET (optional MAX_APK_MB, default 20).
4. Local: `npx netlify link` then `npm run dev` (Blobs work in netlify dev). Deploy: push to Git and connect the repo in Netlify (build: none, publish: public).
5. Admin: footer "Terms & Conditions" → "Publisher sign in".
Data lives in Netlify Blobs (no separate DB or storage setup).
