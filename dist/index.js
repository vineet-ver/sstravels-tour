// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
import { pgTable, text, serial, integer, boolean, date, timestamp, pgEnum, json } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
var paymentMethodEnum = pgEnum("payment_method", [
  "paytm",
  "phonepe",
  "gpay",
  "cash"
]);
var paymentStatusEnum = pgEnum("payment_status", [
  "pending",
  "completed",
  "failed",
  "refunded"
]);
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  email: text("email").notNull(),
  fullName: text("full_name").notNull(),
  isAdmin: boolean("is_admin").default(false)
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true,
  fullName: true,
  isAdmin: true
});
var categoryEnum = pgEnum("category", [
  "wedding",
  "business",
  "party",
  "tour",
  "event",
  "outdoor",
  "luxury"
]);
var cars = pgTable("cars", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  category: categoryEnum("category").notNull(),
  description: text("description").notNull(),
  imageUrl: text("image_url").notNull(),
  seatingCapacity: integer("seating_capacity").notNull(),
  fuelType: text("fuel_type").notNull(),
  hasAC: boolean("has_ac").default(true),
  hasGPS: boolean("has_gps").default(false),
  hasBluetooth: boolean("has_bluetooth").default(false),
  hasLeatherSeats: boolean("has_leather_seats").default(false),
  pricePerDay: integer("price_per_day").notNull(),
  // stored in cents
  isAvailable: boolean("is_available").default(true)
});
var insertCarSchema = createInsertSchema(cars).omit({
  id: true
});
var bookings = pgTable("bookings", {
  id: serial("id").primaryKey(),
  carId: integer("car_id").notNull(),
  customerName: text("customer_name").notNull(),
  customerEmail: text("customer_email").notNull(),
  customerPhone: text("customer_phone").notNull(),
  pickupDate: date("pickup_date").notNull(),
  returnDate: date("return_date").notNull(),
  totalPrice: integer("total_price").notNull(),
  // stored in cents
  status: text("status").notNull().default("pending"),
  // pending, confirmed, completed, cancelled
  createdAt: timestamp("created_at").defaultNow()
});
var insertBookingSchema = createInsertSchema(bookings).omit({
  id: true,
  createdAt: true
});
var testimonials = pgTable("testimonials", {
  id: serial("id").primaryKey(),
  customerName: text("customer_name").notNull(),
  customerType: text("customer_type").notNull(),
  rating: integer("rating").notNull(),
  comment: text("comment").notNull()
});
var insertTestimonialSchema = createInsertSchema(testimonials).omit({
  id: true
});
var payments = pgTable("payments", {
  id: serial("id").primaryKey(),
  bookingId: integer("booking_id").notNull(),
  amount: integer("amount").notNull(),
  // stored in paise (1 INR = 100 paise)
  method: paymentMethodEnum("method").notNull(),
  status: paymentStatusEnum("status").notNull().default("pending"),
  transactionId: text("transaction_id"),
  paymentQrUrl: text("payment_qr_url"),
  // URL to the QR code image
  paymentQrData: text("payment_qr_data"),
  // The data encoded in the QR code
  paymentMeta: json("payment_meta"),
  // Additional payment metadata
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var insertPaymentSchema = createInsertSchema(payments).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var carsRelations = relations(cars, ({ many }) => ({
  bookings: many(bookings)
}));
var bookingsRelations = relations(bookings, ({ one, many }) => ({
  car: one(cars, {
    fields: [bookings.carId],
    references: [cars.id]
  }),
  payments: many(payments)
}));
var paymentsRelations = relations(payments, ({ one }) => ({
  booking: one(bookings, {
    fields: [payments.bookingId],
    references: [bookings.id]
  })
}));

// server/storage.ts
import session from "express-session";
import createMemoryStore from "memorystore";
import connectPg from "connect-pg-simple";
import * as pg from "@neondatabase/serverless";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/neon-serverless";
var { Pool } = pg;
var pool = new Pool({
  connectionString: process.env.DATABASE_URL
});
var db = drizzle(pool);
var MemoryStore = createMemoryStore(session);
var PostgresSessionStore = connectPg(session);
var initialCars = [
  {
    id: 1,
    name: "Sedan",
    category: "wedding",
    description: "A comfortable and stylish sedan perfect for business travel, daily commuting, weddings, and special events. Ideal for short to medium distance trips like Noida to Vrindavan.",
    imageUrl: "https://images.unsplash.com/photo-1618843479313-40f8afb4b4d8?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 4,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 3e3,
    isAvailable: true
  },
  {
    id: 2,
    name: "XUV",
    category: "wedding",
    description: "A versatile SUV with excellent ground clearance and spacious interiors. Perfect for longer trips like Noida to Jind, offering comfort and reliability.",
    imageUrl: "https://images.unsplash.com/photo-1519641471654-76ce0107ad1b?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1171&q=80",
    seatingCapacity: 5,
    fuelType: "Diesel",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 4e3,
    isAvailable: true
  },
  {
    id: 3,
    name: "Desire",
    category: "wedding",
    description: "A stylish hatchback with modern features and good fuel efficiency. Great for trips like Noida to Haridwar, balancing comfort with economy.",
    imageUrl: "https://images.unsplash.com/photo-1552519507-da3b142c6e3d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 5,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 3e3,
    isAvailable: true
  },
  {
    id: 4,
    name: "Aura",
    category: "wedding",
    description: "A premium sedan with advanced technology and luxurious interiors. Ideal for spiritual journeys like Noida to Rishikesh, ensuring a comfortable ride.",
    imageUrl: "https://images.unsplash.com/photo-1617814076367-b759c7d7e738?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 4,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 3e3,
    isAvailable: true
  },
  {
    id: 5,
    name: "Etios",
    category: "wedding",
    description: "A reliable and fuel-efficient sedan with spacious interiors. Perfect for hill station trips like Noida to Dehradun, offering stability and comfort.",
    imageUrl: "https://images.unsplash.com/photo-1606664742090-205398aaa1cb?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 5,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 3e3,
    isAvailable: true
  },
  {
    id: 6,
    name: "Ertiga",
    category: "wedding",
    description: "A versatile MPV with excellent space and comfort. Ideal for group travels like Noida to Chandigarh, with ample space for luggage.",
    imageUrl: "https://images.unsplash.com/photo-1553440569-bcc63803a83d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1125&q=80",
    seatingCapacity: 7,
    fuelType: "Diesel",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 4e3,
    isAvailable: true
  },
  {
    id: 7,
    name: "Innova",
    category: "wedding",
    description: "A premium MPV with luxurious interiors and excellent comfort. Perfect for long journeys like Noida to Lucknow, offering unmatched comfort and reliability.",
    imageUrl: "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 7,
    fuelType: "Diesel",
    hasAC: true,
    hasGPS: false,
    hasBluetooth: false,
    hasLeatherSeats: false,
    pricePerDay: 4e3,
    isAvailable: true
  },
  {
    id: 8,
    name: "BMW 5 Series",
    category: "luxury",
    description: "Experience ultimate luxury with the BMW 5 Series. Perfect for business executives and special occasions, featuring premium leather seats, advanced technology, and superior comfort.",
    imageUrl: "https://images.unsplash.com/photo-1555215695-3004980ad54e?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 5,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: true,
    hasBluetooth: true,
    hasLeatherSeats: true,
    pricePerDay: 5e3,
    isAvailable: true
  },
  {
    id: 9,
    name: "Mercedes-Benz E-Class",
    category: "luxury",
    description: "The epitome of luxury and sophistication. The Mercedes-Benz E-Class offers unparalleled comfort, advanced safety features, and a smooth ride perfect for business and special occasions.",
    imageUrl: "https://images.unsplash.com/photo-1618843479313-40f8afb4b4d8?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 5,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: true,
    hasBluetooth: true,
    hasLeatherSeats: true,
    pricePerDay: 5e3,
    isAvailable: true
  },
  {
    id: 10,
    name: "Audi A6",
    category: "luxury",
    description: "The Audi A6 combines luxury with performance. Featuring premium interiors, advanced technology, and a powerful engine, it's perfect for those who demand the best.",
    imageUrl: "https://images.unsplash.com/photo-1606664742090-205398aaa1cb?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1170&q=80",
    seatingCapacity: 5,
    fuelType: "Petrol",
    hasAC: true,
    hasGPS: true,
    hasBluetooth: true,
    hasLeatherSeats: true,
    pricePerDay: 5e3,
    isAvailable: true
  },
  {
    id: 11,
    name: "Mahindra Thar",
    category: "luxury",
    description: "The rugged yet luxurious Mahindra Thar is perfect for adventure seekers. With its powerful engine and premium interiors, it's ideal for both city drives and off-road adventures.",
    imageUrl: "https://images.unsplash.com/photo-1519641471654-76ce0107ad1b?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1171&q=80",
    seatingCapacity: 4,
    fuelType: "Diesel",
    hasAC: true,
    hasGPS: true,
    hasBluetooth: true,
    hasLeatherSeats: true,
    pricePerDay: 5e3,
    isAvailable: true
  },
  {
    id: 12,
    name: "Tempo Traveller",
    category: "luxury",
    description: "A spacious and comfortable luxury bus perfect for group travel. Features premium seating, entertainment systems, and ample luggage space for a comfortable journey.",
    imageUrl: "https://images.unsplash.com/photo-1553440569-bcc63803a83d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1125&q=80",
    seatingCapacity: 12,
    fuelType: "Diesel",
    hasAC: true,
    hasGPS: true,
    hasBluetooth: true,
    hasLeatherSeats: true,
    pricePerDay: 5e3,
    isAvailable: true
  }
];
var initialTestimonials = [
  {
    id: 1,
    customerName: "Sarah Johnson",
    customerType: "Wedding Client",
    rating: 5,
    comment: "The service was exceptional from start to finish. The car was immaculate, the driver professional, and the whole experience made our wedding day even more special!"
  },
  {
    id: 2,
    customerName: "David Chen",
    customerType: "Business Client",
    rating: 5,
    comment: "Booking was simple and straightforward. The luxury sedan was perfect for our business meeting, making a great impression on our clients. Will definitely use again."
  },
  {
    id: 3,
    customerName: "Michael Brown",
    customerType: "Family Travel",
    rating: 4.5,
    comment: "We rented a luxury SUV for our family vacation and it was perfect. Spacious, comfortable, and the customer service was top-notch. Highly recommend!"
  }
];
var MemStorage = class {
  users;
  cars;
  bookings;
  testimonials;
  payments;
  userIdCounter;
  carIdCounter;
  bookingIdCounter;
  testimonialIdCounter;
  paymentIdCounter;
  sessionStore;
  constructor() {
    this.users = /* @__PURE__ */ new Map();
    this.cars = /* @__PURE__ */ new Map();
    this.bookings = /* @__PURE__ */ new Map();
    this.testimonials = /* @__PURE__ */ new Map();
    this.payments = /* @__PURE__ */ new Map();
    this.userIdCounter = 1;
    this.carIdCounter = initialCars.length + 1;
    this.bookingIdCounter = 1;
    this.testimonialIdCounter = initialTestimonials.length + 1;
    this.paymentIdCounter = 1;
    initialCars.forEach((car) => this.cars.set(car.id, car));
    initialTestimonials.forEach((testimonial) => this.testimonials.set(testimonial.id, testimonial));
    const MemoryStore2 = createMemoryStore(session);
    this.sessionStore = new MemoryStore2({
      checkPeriod: 864e5
      // 24 hours
    });
  }
  // User methods
  async getUser(id) {
    return this.users.get(id);
  }
  async getUserByUsername(username) {
    return Array.from(this.users.values()).find(
      (user) => user.username === username
    );
  }
  async createUser(userData) {
    const id = this.userIdCounter++;
    const user = {
      ...userData,
      id,
      isAdmin: userData.isAdmin ?? false
    };
    this.users.set(id, user);
    return user;
  }
  async getAllUsers() {
    return Array.from(this.users.values());
  }
  // Car methods
  async getCar(id) {
    return this.cars.get(id);
  }
  async getAllCars() {
    return Array.from(this.cars.values());
  }
  async getCarsByCategory(category) {
    return Array.from(this.cars.values()).filter((car) => car.category === category);
  }
  async searchCars(query, category) {
    let filteredCars = Array.from(this.cars.values());
    if (category) {
      filteredCars = filteredCars.filter((car) => car.category === category);
    }
    if (query) {
      const lowercaseQuery = query.toLowerCase();
      filteredCars = filteredCars.filter(
        (car) => car.name.toLowerCase().includes(lowercaseQuery) || car.description.toLowerCase().includes(lowercaseQuery)
      );
    }
    return filteredCars;
  }
  async createCar(car) {
    const id = this.carIdCounter++;
    const newCar = {
      ...car,
      id,
      hasAC: car.hasAC ?? true,
      isAvailable: car.isAvailable ?? true
    };
    this.cars.set(id, newCar);
    return newCar;
  }
  async updateCar(id, car) {
    const existingCar = this.cars.get(id);
    if (!existingCar) return void 0;
    const updatedCar = { ...existingCar, ...car };
    this.cars.set(id, updatedCar);
    return updatedCar;
  }
  async deleteCar(id) {
    return this.cars.delete(id);
  }
  // Booking methods
  async getBooking(id) {
    return this.bookings.get(id);
  }
  async getAllBookings() {
    return Array.from(this.bookings.values());
  }
  async getBookingsByCarId(carId) {
    return Array.from(this.bookings.values()).filter((booking) => booking.carId === carId);
  }
  async createBooking(booking) {
    const id = this.bookingIdCounter++;
    const newBooking = {
      id,
      carId: booking.carId,
      customerName: booking.customerName,
      customerEmail: booking.customerEmail,
      customerPhone: booking.customerPhone,
      pickupDate: booking.pickupDate,
      returnDate: booking.returnDate,
      totalPrice: booking.totalPrice,
      status: booking.status ?? "pending",
      createdAt: /* @__PURE__ */ new Date()
    };
    this.bookings.set(id, newBooking);
    return newBooking;
  }
  async updateBookingStatus(id, status) {
    const booking = this.bookings.get(id);
    if (!booking) return void 0;
    const updatedBooking = { ...booking, status };
    this.bookings.set(id, updatedBooking);
    return updatedBooking;
  }
  // Testimonial methods
  async getAllTestimonials() {
    return Array.from(this.testimonials.values());
  }
  async createTestimonial(testimonial) {
    const id = this.testimonialIdCounter++;
    const newTestimonial = { ...testimonial, id };
    this.testimonials.set(id, newTestimonial);
    return newTestimonial;
  }
  // Payment methods
  async getPayment(id) {
    return this.payments.get(id);
  }
  async getPaymentsByBookingId(bookingId) {
    return Array.from(this.payments.values()).filter((payment) => payment.bookingId === bookingId);
  }
  async createPayment(payment) {
    const id = this.paymentIdCounter++;
    const newPayment = {
      ...payment,
      id,
      transactionId: payment.transactionId || null,
      paymentQrUrl: payment.paymentQrUrl || null,
      paymentQrData: payment.paymentQrData || null,
      paymentMeta: payment.paymentMeta || null,
      status: payment.status || "pending",
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.payments.set(id, newPayment);
    return newPayment;
  }
  async updatePaymentStatus(id, status) {
    const payment = this.payments.get(id);
    if (!payment) return void 0;
    const updatedPayment = {
      ...payment,
      status,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.payments.set(id, updatedPayment);
    return updatedPayment;
  }
  async generatePaymentQR(bookingId, method, amount) {
    const paymentQrUrl = `https://fake-qr-generator.example/qr?bookingId=${bookingId}&amount=${amount}&method=${method}&t=${Date.now()}`;
    const paymentQrData = `upi://pay?pa=example@upi&pn=CarRental&am=${amount / 100}&cu=INR&tn=Booking${bookingId}`;
    const payment = {
      bookingId,
      amount,
      method,
      status: "pending",
      paymentQrUrl,
      paymentQrData,
      paymentMeta: { timestamp: (/* @__PURE__ */ new Date()).toISOString() }
    };
    return this.createPayment(payment);
  }
};
var storage = new MemStorage();

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "car-booking-secret-key",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      maxAge: 1e3 * 60 * 60 * 24
      // 1 day
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !await comparePasswords(password, user.password)) {
          return done(null, false);
        } else {
          return done(null, user);
        }
      } catch (error) {
        return done(error);
      }
    })
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const user = await storage.createUser({
        ...req.body,
        password: await hashPassword(req.body.password),
        isAdmin: false
        // Force regular users, admins can only be created manually
      });
      req.login(user, (err) => {
        if (err) return next(err);
        const { password, ...userWithoutPassword } = user;
        res.status(201).json(userWithoutPassword);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", passport.authenticate("local"), (req, res) => {
    const { password, ...userWithoutPassword } = req.user;
    res.status(200).json(userWithoutPassword);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const { password, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
  });
  (async () => {
    try {
      const adminUser = await storage.getUserByUsername("admin");
      if (!adminUser) {
        const admin = await storage.createUser({
          username: "admin",
          password: await hashPassword("admin123"),
          isAdmin: true
        });
        console.log("Admin user created");
      }
    } catch (error) {
      console.error("Error creating admin user:", error);
    }
  })();
}

// server/routes.ts
import { fromZodError } from "zod-validation-error";
import nodemailer from "nodemailer";
var isAdmin = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: "Forbidden: Admin access required" });
  }
  next();
};
var transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "shuklamrsk682@gmail.com",
    pass: process.env.EMAIL_PASSWORD
  }
});
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.get("/api/cars", async (req, res) => {
    try {
      const cars2 = await storage.getAllCars();
      res.json(cars2);
    } catch (error) {
      res.status(500).json({ message: "Error fetching cars" });
    }
  });
  app2.get("/api/cars/search", async (req, res) => {
    try {
      const { query, category } = req.query;
      const cars2 = await storage.searchCars(
        query,
        category
      );
      res.json(cars2);
    } catch (error) {
      res.status(500).json({ message: "Error searching cars" });
    }
  });
  app2.get("/api/cars/category/:category", async (req, res) => {
    try {
      const { category } = req.params;
      const cars2 = await storage.getCarsByCategory(category);
      res.json(cars2);
    } catch (error) {
      res.status(500).json({ message: "Error fetching cars by category" });
    }
  });
  app2.get("/api/cars/:id", async (req, res) => {
    try {
      const car = await storage.getCar(parseInt(req.params.id));
      if (!car) {
        return res.status(404).json({ message: "Car not found" });
      }
      res.json(car);
    } catch (error) {
      res.status(500).json({ message: "Error fetching car" });
    }
  });
  app2.post("/api/admin/cars", isAdmin, async (req, res) => {
    try {
      const result = insertCarSchema.safeParse(req.body);
      if (!result.success) {
        const validationError = fromZodError(result.error);
        return res.status(400).json({ message: validationError.message });
      }
      const car = await storage.createCar(result.data);
      res.status(201).json(car);
    } catch (error) {
      res.status(500).json({ message: "Error creating car" });
    }
  });
  app2.put("/api/admin/cars/:id", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const existingCar = await storage.getCar(id);
      if (!existingCar) {
        return res.status(404).json({ message: "Car not found" });
      }
      const updatedCar = await storage.updateCar(id, req.body);
      res.json(updatedCar);
    } catch (error) {
      res.status(500).json({ message: "Error updating car" });
    }
  });
  app2.delete("/api/admin/cars/:id", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteCar(id);
      if (!deleted) {
        return res.status(404).json({ message: "Car not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Error deleting car" });
    }
  });
  app2.get("/api/bookings/:id", async (req, res) => {
    try {
      const booking = await storage.getBooking(parseInt(req.params.id));
      if (!booking) {
        return res.status(404).json({ message: "Booking not found" });
      }
      res.json(booking);
    } catch (error) {
      res.status(500).json({ message: "Error fetching booking" });
    }
  });
  app2.post("/api/bookings", async (req, res) => {
    try {
      const result = insertBookingSchema.safeParse(req.body);
      if (!result.success) {
        const validationError = fromZodError(result.error);
        return res.status(400).json({ message: validationError.message });
      }
      const car = await storage.getCar(result.data.carId);
      if (!car) {
        return res.status(404).json({ message: "Car not found" });
      }
      if (!car.isAvailable) {
        return res.status(400).json({ message: "Car is not available for booking" });
      }
      const pickupDate = new Date(result.data.pickupDate);
      const returnDate = new Date(result.data.returnDate);
      const days = Math.ceil((returnDate.getTime() - pickupDate.getTime()) / (1e3 * 60 * 60 * 24));
      if (days <= 0) {
        return res.status(400).json({ message: "Return date must be after pickup date" });
      }
      const totalPrice = car.pricePerDay * days;
      const booking = await storage.createBooking({
        ...result.data,
        totalPrice
      });
      res.status(201).json(booking);
    } catch (error) {
      res.status(500).json({ message: "Error creating booking" });
    }
  });
  app2.get("/api/admin/bookings", isAdmin, async (req, res) => {
    try {
      const bookings2 = await storage.getAllBookings();
      res.json(bookings2);
    } catch (error) {
      res.status(500).json({ message: "Error fetching bookings" });
    }
  });
  app2.put("/api/admin/bookings/:id/status", isAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { status } = req.body;
      if (!["pending", "confirmed", "completed", "cancelled"].includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
      }
      const booking = await storage.updateBookingStatus(id, status);
      if (!booking) {
        return res.status(404).json({ message: "Booking not found" });
      }
      res.json(booking);
    } catch (error) {
      res.status(500).json({ message: "Error updating booking status" });
    }
  });
  app2.get("/api/testimonials", async (req, res) => {
    try {
      const testimonials2 = await storage.getAllTestimonials();
      res.json(testimonials2);
    } catch (error) {
      res.status(500).json({ message: "Error fetching testimonials" });
    }
  });
  app2.post("/api/testimonials", async (req, res) => {
    try {
      const result = insertTestimonialSchema.safeParse(req.body);
      if (!result.success) {
        const validationError = fromZodError(result.error);
        return res.status(400).json({ message: validationError.message });
      }
      const testimonial = await storage.createTestimonial(result.data);
      res.status(201).json(testimonial);
    } catch (error) {
      res.status(500).json({ message: "Error creating testimonial" });
    }
  });
  app2.get("/api/payments/:id", async (req, res) => {
    try {
      const payment = await storage.getPayment(parseInt(req.params.id));
      if (!payment) {
        return res.status(404).json({ message: "Payment not found" });
      }
      res.json(payment);
    } catch (error) {
      res.status(500).json({ message: "Error fetching payment" });
    }
  });
  app2.get("/api/bookings/:id/payments", async (req, res) => {
    try {
      const bookingId = parseInt(req.params.id);
      const payments2 = await storage.getPaymentsByBookingId(bookingId);
      res.json(payments2);
    } catch (error) {
      console.error("Error fetching payments:", error);
      res.status(500).json({ error: "Failed to fetch payments" });
    }
  });
  app2.post("/api/bookings/:id/generate-payment-qr", async (req, res) => {
    try {
      const bookingId = parseInt(req.params.id);
      const { method } = req.body;
      if (!["paytm", "phonepe", "gpay", "cash"].includes(method)) {
        return res.status(400).json({ error: "Invalid payment method" });
      }
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      const payment = await storage.generatePaymentQR(bookingId, method, booking.totalPrice);
      res.json(payment);
    } catch (error) {
      console.error("Error generating payment QR:", error);
      res.status(500).json({ error: "Failed to generate payment QR" });
    }
  });
  app2.put("/api/payments/:id/status", async (req, res) => {
    try {
      const paymentId = parseInt(req.params.id);
      const { status } = req.body;
      if (!["pending", "completed", "failed", "refunded"].includes(status)) {
        return res.status(400).json({ error: "Invalid payment status" });
      }
      const payment = await storage.updatePaymentStatus(paymentId, status);
      res.json(payment);
    } catch (error) {
      console.error("Error updating payment status:", error);
      res.status(500).json({ error: "Failed to update payment status" });
    }
  });
  app2.post("/api/admin/reset-storage", isAdmin, async (req, res) => {
    try {
      const cars2 = await storage.getAllCars();
      for (const car of cars2) {
        await storage.deleteCar(car.id);
      }
      const initialCars2 = [
        {
          name: "Sedan",
          category: "wedding",
          description: "A comfortable and stylish sedan perfect for business travel, daily commuting, weddings, and special events.",
          imageUrl: "https://images.unsplash.com/photo-1555652736-e92021d28a39?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 4,
          fuelType: "Petrol",
          hasAC: true,
          pricePerDay: 19900,
          isAvailable: true
        },
        {
          name: "XUV",
          category: "wedding",
          description: "A versatile SUV with excellent ground clearance and spacious interiors, ideal for family trips, outdoor adventures, weddings, and corporate events.",
          imageUrl: "https://images.unsplash.com/photo-1503376780353-7e6692767b70?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 5,
          fuelType: "Diesel",
          hasAC: true,
          pricePerDay: 24900,
          isAvailable: true
        },
        {
          name: "Desire",
          category: "wedding",
          description: "A stylish hatchback with modern features and good fuel efficiency, perfect for city driving, small family trips, weddings, and special occasions.",
          imageUrl: "https://images.unsplash.com/photo-1494976388531-d1058494cdd8?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 5,
          fuelType: "Petrol",
          hasAC: true,
          pricePerDay: 14900,
          isAvailable: true
        },
        {
          name: "Aura",
          category: "wedding",
          description: "A premium sedan with advanced technology and luxurious interiors, perfect for business executives, special occasions, weddings, and corporate events.",
          imageUrl: "https://images.unsplash.com/photo-1617814076367-b759c7d7e738?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 4,
          fuelType: "Petrol",
          hasAC: true,
          pricePerDay: 18900,
          isAvailable: true
        },
        {
          name: "Etios",
          category: "wedding",
          description: "A reliable and fuel-efficient sedan with spacious interiors, ideal for long-distance travel, family trips, weddings, and special events.",
          imageUrl: "https://images.unsplash.com/photo-1606664742090-205398aaa1cb?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 5,
          fuelType: "Petrol",
          hasAC: true,
          pricePerDay: 16900,
          isAvailable: true
        },
        {
          name: "Ertiga",
          category: "wedding",
          description: "A versatile MPV with excellent space and comfort, perfect for family trips, airport transfers, group travel, weddings, and corporate events.",
          imageUrl: "https://images.unsplash.com/photo-1553440569-bcc63803a83d?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1125&q=80",
          seatingCapacity: 7,
          fuelType: "Diesel",
          hasAC: true,
          pricePerDay: 22900,
          isAvailable: true
        },
        {
          name: "Innova",
          category: "wedding",
          description: "A premium MPV with luxurious interiors and excellent comfort, perfect for weddings, family trips, corporate events, and special occasions.",
          imageUrl: "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80",
          seatingCapacity: 7,
          fuelType: "Diesel",
          hasAC: true,
          pricePerDay: 29900,
          isAvailable: true
        }
      ];
      for (const car of initialCars2) {
        await storage.createCar(car);
      }
      res.json({ message: "Storage reset successfully", cars: await storage.getAllCars() });
    } catch (error) {
      res.status(500).json({ message: "Error resetting storage" });
    }
  });
  app2.post("/api/newsletter/subscribe", async (req, res) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }
      const mailOptions = {
        from: "Car Travel Booking <noreply@cartravelbooking.com>",
        to: "shuklamrsk682@gmail.com",
        subject: "New Newsletter Subscription",
        html: `
          <h2>New Newsletter Subscription</h2>
          <p>A new user has subscribed to the newsletter:</p>
          <p><strong>Email:</strong> ${email}</p>
          <p>Date: ${(/* @__PURE__ */ new Date()).toLocaleString()}</p>
        `
      };
      await transporter.sendMail(mailOptions);
      res.status(200).json({
        message: "Newsletter subscription successful",
        email
      });
    } catch (error) {
      console.error("Newsletter subscription error:", error);
      res.status(500).json({
        error: "Failed to process newsletter subscription"
      });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import path from "path";
import { createServer as createServer2 } from "vite";
function log(message, level = "info") {
  const timestamp2 = (/* @__PURE__ */ new Date()).toLocaleTimeString();
  console.log(`${timestamp2} [express] ${message}`);
}
async function setupVite(app2, server) {
  const vite = await createServer2({
    server: {
      middlewareMode: true,
      hmr: {
        server
      }
    },
    appType: "spa"
  });
  app2.use(vite.middlewares);
  app2.use("*", (req, res, next) => {
    if (req.originalUrl.startsWith("/api")) {
      return next();
    }
    res.sendFile(path.resolve(__dirname, "../client/index.html"));
  });
}
function serveStatic(app2) {
  app2.use(express.static(path.resolve(__dirname, "../client")));
  app2.get("*", (req, res, next) => {
    if (req.originalUrl.startsWith("/api")) {
      return next();
    }
    res.sendFile(path.resolve(__dirname, "../client/index.html"));
  });
}

// server/index.ts
import dotenv from "dotenv";
dotenv.config();
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path2 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path2.startsWith("/api")) {
      let logLine = `${req.method} ${path2} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
app.use((err, _req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  log(`Error: ${message}`, "error");
  res.status(status).json({ message });
});
(async () => {
  try {
    const server = await registerRoutes(app);
    if (process.env.NODE_ENV !== "production") {
      await setupVite(app, server);
      log("Vite development server setup complete");
    } else {
      serveStatic(app);
      log("Static file serving setup complete");
    }
    const port = parseInt(process.env.PORT || "3000", 10);
    server.listen(port, "0.0.0.0", () => {
      log(`Server running on port ${port}`);
      log(`Environment: ${process.env.NODE_ENV || "development"}`);
    });
  } catch (error) {
    log(`Failed to start server: ${error}`, "error");
    process.exit(1);
  }
})();
