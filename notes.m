let addHeaders = {
  "Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests",
  "Strict-Transport-Security": "max-age=1000",
  "X-Frame-Options": "SAMEORIGIN",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin"
}

let removeHeaders = [
  "Server",
  "Public-Key-Pins",
  "X-Powered-By",
  "X-AspNet-Version"
]