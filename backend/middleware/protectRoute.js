import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ENV_VARS } from "../config/envVars.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies["jwt-netflix"];

    if (!token) {
      return res.status(401).json({ success: false, message: "Unauthorized - No Token Provided" });
    }

    // Verify the token
    const decoded = jwt.verify(token, ENV_VARS.JWT_SECRET);

    if (!decoded) {
      return res.status(401).json({ success: false, message: "Unauthorized - Invalid Token" });
    }

    // Find user by ID from the decoded token
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Attach user to request object for use in other routes
    req.user = user;

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware:", error.message);

    // Handle specific error if token expired
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, message: "Token expired" });
    }

    // General error handling
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};
