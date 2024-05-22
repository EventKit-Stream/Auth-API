module.exports = {
  apps: [
    {
      name: "server-app",
      script: "gunicorn -w 4 -k uvicorn.workers.UvicornWorker --chdir ./server main:app -b 0.0.0.0:79"
    },
    {
      name: "client-app",
      script: "npx serve ./client/.output/public -p 81"
    },
    {
      name: "nginx-app",
      script: 'nginx -g "daemon off;"',
    }
  ]
}