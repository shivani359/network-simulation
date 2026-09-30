import { Router, type IRouter } from "express";
import healthRouter from "./health";
import idsRouter from "./ids";

const router: IRouter = Router();

router.use(healthRouter);
router.use(idsRouter);

export default router;
