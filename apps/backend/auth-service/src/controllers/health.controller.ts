import sendResponse from "@/src/utils/sent-responst";
import { Controller, Get, Route, Tags } from "tsoa";

@Tags("Health API")
@Route('v1/auth')
export class HealthController extends Controller {
  @Get("/health")
  public async getHealth(): Promise<{ message: string }> {
    try {
      return sendResponse({ message: 'OK' })
    } catch (error) {
      throw error;
    }
  }
}