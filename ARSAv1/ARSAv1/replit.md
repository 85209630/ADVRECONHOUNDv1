# replit.md

## Overview

This is a comprehensive cybersecurity reconnaissance and vulnerability assessment application built with a modern full-stack architecture. The system provides automated security scanning capabilities, including subdomain enumeration, vulnerability assessment, technology stack detection, and AI-powered analysis through OpenAI integration.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript
- **Build Tool**: Vite for fast development and optimized builds
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack Query (React Query) for server state management
- **UI Framework**: Radix UI primitives with shadcn/ui components
- **Styling**: Tailwind CSS with CSS custom properties for theming
- **Real-time Updates**: WebSocket connection for live scan progress updates

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ESM modules
- **Database**: PostgreSQL with Drizzle ORM
- **Real-time Communication**: WebSocket server for bidirectional client-server communication
- **External Services**: OpenAI API for vulnerability analysis and reporting
- **Development**: Hot module replacement via Vite integration

### Database Schema
- **Users**: User authentication and management
- **Scans**: Core scan records with status tracking and JSON results storage
- **Vulnerabilities**: Structured vulnerability data with CVSS scoring
- **Subdomains**: Discovered subdomains with IP resolution and technology detection
- **Technologies**: Identified technology stack with confidence scoring

## Key Components

### Security Services
- **ReconnaissanceService**: Handles subdomain enumeration, port scanning, DNS record collection, and technology fingerprinting
- **Gemini AI Integration**: Automated vulnerability analysis, technology assessment, and comprehensive report generation using Google's Gemini API
- **Real-time Progress**: WebSocket-based progress updates during scan execution

### Data Management
- **Storage Layer**: Abstracted storage interface with PostgreSQL database implementation
- **Database Integration**: Drizzle ORM with PostgreSQL for persistent data storage
- **Type Safety**: Zod schemas for runtime validation and TypeScript integration

### User Interface
- **Dashboard**: Central hub for scan management and results visualization
- **Scan Form**: Target input with validation and scan configuration options
- **Results Display**: Tabbed interface for vulnerabilities, subdomains, and technology stack
- **Progress Tracking**: Real-time scan progress indicators with WebSocket updates

## Data Flow

1. **Scan Initiation**: User submits target through validated form
2. **Scan Processing**: Backend creates scan record and initiates reconnaissance
3. **Data Collection**: Multiple reconnaissance techniques gather security intelligence
4. **AI Analysis**: Gemini AI processes raw data for vulnerability assessment
5. **Real-time Updates**: WebSocket broadcasts progress to connected clients
6. **Result Storage**: Structured data persisted to database with relationships
7. **Report Generation**: Comprehensive markdown reports with actionable insights

## External Dependencies

### Production Dependencies
- **Database**: Neon serverless PostgreSQL for cloud-native data persistence
- **AI Services**: Google Gemini API for intelligent vulnerability analysis with generous free tier
- **UI Components**: Radix UI ecosystem for accessible, customizable interfaces
- **Validation**: Zod for schema validation and type safety

### Development Tools
- **Build System**: Vite with React plugin and TypeScript support
- **Database Management**: Drizzle Kit for schema migrations and database operations
- **Code Quality**: TypeScript strict mode with comprehensive type checking
- **Development Experience**: Hot reload, error overlays, and Replit integration

## Deployment Strategy

### Development Environment
- **Local Development**: Vite dev server with Express API backend
- **Database**: PostgreSQL database with Drizzle ORM for persistent storage
- **Real-time Features**: WebSocket server integrated with HTTP server
- **Asset Management**: Vite handles static asset optimization and bundling

### Production Build
- **Frontend**: Vite production build with optimized bundles
- **Backend**: esbuild compilation for efficient Node.js deployment
- **Database**: Drizzle migrations for schema management
- **Environment**: NODE_ENV-based configuration switching

### Architecture Decisions

**Monorepo Structure**: Organized into client, server, and shared directories for clear separation of concerns while maintaining code sharing capabilities.

**Real-time Communication**: WebSocket integration provides immediate feedback during long-running security scans, enhancing user experience.

**AI-Powered Analysis**: Google Gemini integration transforms raw reconnaissance data into actionable security insights, reducing manual analysis overhead.

**Type-Safe Database**: Drizzle ORM with TypeScript provides compile-time safety and runtime validation for database operations.

**Component-Based UI**: Radix UI primitives ensure accessibility compliance while maintaining design flexibility through shadcn/ui abstractions.