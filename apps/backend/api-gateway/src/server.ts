import app from "@/src/app";
import configs from "@/src/config";

function run() {
  app.listen(configs.port, () => {
    console.log(`==================== API Gateway ====================`)
    console.log(`API Geteway Service running on http://localhost:${configs.port}`);
  });
}

run();