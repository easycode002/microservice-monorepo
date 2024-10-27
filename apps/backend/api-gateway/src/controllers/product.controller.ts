import { Controller, Route, Get, Tags } from "tsoa";

export interface IItem {
  name: string;
  category: string;
  price: number;
}

@Tags('API Gateway')
@Route("/v1/products")
export class ProductController extends Controller {
  @Get("/")
  public getAllProducts() {
    return [{ id: 1, name: "Cherrie", category: "fruit", price: 10.2 }];
  }
}
