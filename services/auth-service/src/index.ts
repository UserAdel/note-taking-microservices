import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import authRouter from "./routes";
import { errorHandler } from "../../../shared/middleware/index";
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;

//setup middleware
app.use(cors());
app.use(helmet());
//parse JSON bodies
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api/auth", authRouter);
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`auth service is running on port ${PORT}`);
  console.log(`Enviroment:${process.env.NODE_ENV}`);
  console.log(`Health check :https://localhost:${PORT}/health`);
});

export default app;
