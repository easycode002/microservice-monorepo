import { Body, Post, Route, Tags } from "tsoa";
import { SignupRequest } from "@/src/services/types/auth-service.type";
import authService from "@/src/services/auth.service";
import sendResponse from "@/src/utils/sent-responst";

@Tags("Auth service")
@Route("v1/auth")
export class AuthController {
  @Post("/signup")
  public async signup(
    @Body() body: SignupRequest
  ): Promise<{ message: string }> {
    try {
      const result = await authService.signup(body);
      return sendResponse({ message: result });
    } catch (error) {
      throw error;
    }
  }
}
export default new AuthController();
