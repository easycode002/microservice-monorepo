import app from "@/src/app";
import configs from "@/src/config";

function run() {
  app.listen(configs.port, () => {
    console.log(`==================== Auth Service ===================`)
    console.log(`Auth Service running on http://localhost:${configs.port}`);
  });
}

run();
