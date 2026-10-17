# Expense Buddy API

Express + MongoDB backend for the Expense Buddy app (login with OTP, expense sync, friends and bill splits).

## Run locally

```sh
cd backend
npm install
# create .env with: MONGODB_URI="mongodb+srv://..."  (and optionally PORT=3001)
npm start
```

## Deploy on Render

Push this folder to a GitHub repo, then in Render: New → Blueprint → pick the repo.
Set `MONGODB_URI` when Render asks for it. In MongoDB Atlas → Network Access, allow `0.0.0.0/0`
(Render's free plan has no fixed IP address).
