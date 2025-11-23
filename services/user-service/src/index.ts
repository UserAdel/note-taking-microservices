import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import userRouter from "./routes";
import { corsOptions, errorHandler } from "../../../shared/middleware/index";
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3002;

//setup middleware
app.use(cors(corsOptions()));
app.use(helmet());
0;
//parse JSON bodies
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/users", userRouter);
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`user service is running on port ${PORT}`);
  console.log(`Enviroment:${process.env.NODE_ENV}`);
  console.log(`Health check :https://localhost:${PORT}/health`);
});

export default app;
