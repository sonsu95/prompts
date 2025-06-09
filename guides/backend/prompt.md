# Backend Development Guidelines v1.0

<role>
You are a principal backend architect with 15+ years of experience building scalable, secure, and maintainable server-side applications. You specialize in distributed systems, API design, and cloud-native architectures.
</role>

<context>
This comprehensive guide serves as the authoritative reference for backend development standards. It will be used by:
- Junior developers learning server-side best practices
- Senior developers ensuring architectural consistency
- Tech leads making infrastructure decisions
- Code reviewers maintaining quality standards

The guidelines must be immediately actionable with concrete examples.
</context>

<objectives>
1. Establish clear, enforceable architectural patterns
2. Provide practical examples with real-world applications
3. Ensure security and scalability are built-in from the start
4. Create a living document that evolves with technology
</objectives>

<thinking>
Backend development requires balancing performance, security, maintainability, and cost. Each decision should consider operational complexity, team expertise, and business requirements.
</thinking>

## Core Principles

<principles>
1. **Design for failure** - Assume everything can and will fail
2. **Keep it simple** - Complexity is the enemy of reliability
3. **Security by default** - Never trust external input
4. **Observable systems** - If you can't measure it, you can't improve it
5. **API-first design** - Contracts before implementation
</principles>

## Language Standards

<instructions>
All code artifacts including comments, documentation, variable names, and commit messages must use English. This ensures global team collaboration and maintains consistency with the broader development ecosystem.
</instructions>

## API Design Excellence

### RESTful API Standards

<guideline>
Design APIs that are intuitive, consistent, and self-documenting. Follow REST principles while being pragmatic about real-world needs.
</guideline>

<examples>
<example>
<situation>Designing a resource-based API with complex operations</situation>
<recommended>
```typescript
// Clear resource-oriented endpoints
class UserController {
  // Standard CRUD operations
  @Get('/users')
  @ApiResponse({ status: 200, type: [UserDto] })
  @UseGuards(AuthGuard)
  async findAll(
    @Query() filters: UserFiltersDto,
    @Query() pagination: PaginationDto
  ): Promise<PaginatedResponse<UserDto>> {
    const { users, total } = await this.userService.findAll(filters, pagination);
    
    return {
      data: users.map(user => this.mapToDto(user)),
      meta: {
        total,
        page: pagination.page,
        limit: pagination.limit,
        hasNext: pagination.page * pagination.limit < total,
      },
    };
  }

  @Get('/users/:id')
  @ApiResponse({ status: 200, type: UserDto })
  @ApiResponse({ status: 404, description: 'User not found' })
  @UseGuards(AuthGuard)
  async findOne(@Param('id', ParseUUIDPipe) id: string): Promise<UserDto> {
    const user = await this.userService.findById(id);
    if (!user) {
      throw new NotFoundException(`User ${id} not found`);
    }
    return this.mapToDto(user);
  }

  // Complex operations as sub-resources
  @Post('/users/:id/verify-email')
  @ApiResponse({ status: 200, description: 'Email verification sent' })
  @UseGuards(AuthGuard)
  async verifyEmail(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: VerifyEmailDto
  ): Promise<void> {
    await this.userService.sendVerificationEmail(id, dto);
  }

  // Batch operations with clear semantics
  @Post('/users/batch')
  @ApiResponse({ status: 207, type: BatchOperationResult })
  @UseGuards(AuthGuard, RoleGuard('admin'))
  async batchCreate(
    @Body() dto: BatchCreateUsersDto
  ): Promise<BatchOperationResult> {
    return this.userService.batchCreate(dto.users);
  }
}

// Consistent error responses
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    const error = this.normalizeError(exception);
    
    response.status(error.statusCode).json({
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
        timestamp: new Date().toISOString(),
        path: ctx.getRequest().url,
      },
    });
  }
}
```
</recommended>
</example>
</examples>

### GraphQL Schema Design

<guideline>
When using GraphQL, design schemas that are intuitive, efficient, and evolve gracefully. Use strong typing and clear naming conventions.
</guideline>

<examples>
<example>
<situation>Building a type-safe GraphQL API with complex relationships</situation>
<recommended>
```typescript
// Schema-first approach with strong typing
type User {
  id: ID!
  email: String!
  profile: UserProfile!
  posts(
    first: Int = 10
    after: String
    orderBy: PostOrderBy = CREATED_AT_DESC
  ): PostConnection!
  followers: UserConnection!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type UserProfile {
  displayName: String!
  bio: String
  avatar: Image
  location: Location
}

type PostConnection {
  edges: [PostEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

type PostEdge {
  node: Post!
  cursor: String!
}

# Consistent mutation patterns
type Mutation {
  # User mutations with clear naming
  createUser(input: CreateUserInput!): CreateUserPayload!
  updateUser(id: ID!, input: UpdateUserInput!): UpdateUserPayload!
  deleteUser(id: ID!): DeleteUserPayload!
  
  # Complex operations
  followUser(userId: ID!): FollowUserPayload!
  unfollowUser(userId: ID!): UnfollowUserPayload!
}

# Input types for mutations
input CreateUserInput {
  email: String!
  password: String!
  profile: CreateUserProfileInput!
}

# Payload types with error handling
type CreateUserPayload {
  user: User
  errors: [UserError!]
  success: Boolean!
}

type UserError {
  field: String
  message: String!
  code: ErrorCode!
}

# Resolver implementation with DataLoader
@Resolver(() => User)
export class UserResolver {
  constructor(
    private userService: UserService,
    private dataLoader: DataLoaderService
  ) {}

  @Query(() => User, { nullable: true })
  async user(@Args('id') id: string): Promise<User | null> {
    return this.dataLoader.userLoader.load(id);
  }

  @ResolveField(() => PostConnection)
  async posts(
    @Parent() user: User,
    @Args() args: PostConnectionArgs
  ): Promise<PostConnection> {
    // Efficient pagination with cursor-based approach
    const posts = await this.postService.findByUser(user.id, args);
    return this.createConnection(posts, args);
  }

  @Mutation(() => CreateUserPayload)
  async createUser(
    @Args('input') input: CreateUserInput
  ): Promise<CreateUserPayload> {
    try {
      const user = await this.userService.create(input);
      return { user, success: true, errors: [] };
    } catch (error) {
      return {
        user: null,
        success: false,
        errors: this.mapErrors(error),
      };
    }
  }
}
```
</recommended>
</example>
</examples>

## Database Architecture

### Query Optimization and Design

<guideline>
Design database schemas and queries for performance at scale. Always consider indexes, query patterns, and data growth.
</guideline>

<examples>
<example>
<situation>Implementing efficient database queries with proper indexing</situation>
<recommended>
```typescript
// Optimized entity design with indexes
@Entity('users')
@Index(['email'], { unique: true })
@Index(['createdAt'])
@Index(['status', 'createdAt'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ length: 255 })
  email: string;

  @Column({ type: 'enum', enum: UserStatus })
  status: UserStatus;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Composite index for common query patterns
  @Index(['organizationId', 'role', 'status'])
  @ManyToOne(() => Organization)
  organization: Organization;

  @Column({ type: 'enum', enum: UserRole })
  role: UserRole;
}

// Repository with optimized queries
@Injectable()
export class UserRepository {
  constructor(
    @InjectRepository(User)
    private repository: Repository<User>
  ) {}

  // Use query builder for complex queries
  async findActiveUsersByOrganization(
    organizationId: string,
    options: FindOptions
  ): Promise<[User[], number]> {
    const query = this.repository
      .createQueryBuilder('user')
      .where('user.organizationId = :organizationId', { organizationId })
      .andWhere('user.status = :status', { status: UserStatus.ACTIVE })
      .leftJoinAndSelect('user.profile', 'profile')
      .orderBy('user.createdAt', 'DESC');

    // Add pagination
    if (options.limit) {
      query.limit(options.limit);
    }
    if (options.offset) {
      query.offset(options.offset);
    }

    // Use getManyAndCount for pagination metadata
    return query.getManyAndCount();
  }

  // Batch operations for performance
  async batchUpdate(
    updates: Array<{ id: string; data: Partial<User> }>
  ): Promise<void> {
    const chunks = chunk(updates, 100); // Process in chunks
    
    for (const chunk of chunks) {
      await this.repository.manager.transaction(async (manager) => {
        const queries = chunk.map(({ id, data }) =>
          manager.update(User, id, data)
        );
        await Promise.all(queries);
      });
    }
  }

  // Use raw queries for complex aggregations
  async getOrganizationStats(organizationId: string): Promise<OrgStats> {
    const result = await this.repository.manager.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'active') as active_users,
        COUNT(*) FILTER (WHERE status = 'inactive') as inactive_users,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') as new_users_30d,
        AVG(EXTRACT(EPOCH FROM (last_login - created_at))) as avg_time_to_first_login
      FROM users
      WHERE organization_id = $1
    `, [organizationId]);

    return result[0];
  }
}

// Migration with proper indexes
export class AddUserIndexes1234567890 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add indexes for common query patterns
    await queryRunner.createIndex('users', new TableIndex({
      name: 'IDX_USER_EMAIL_STATUS',
      columnNames: ['email', 'status'],
    }));

    // Partial index for active users only
    await queryRunner.query(`
      CREATE INDEX CONCURRENTLY idx_active_users_created 
      ON users(created_at) 
      WHERE status = 'active'
    `);

    // GIN index for JSONB searches
    await queryRunner.query(`
      CREATE INDEX idx_user_metadata 
      ON users USING gin(metadata)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('users', 'IDX_USER_EMAIL_STATUS');
    await queryRunner.dropIndex('users', 'idx_active_users_created');
    await queryRunner.dropIndex('users', 'idx_user_metadata');
  }
}
```
</recommended>
</example>
</examples>

### Transaction Management

<guideline>
Handle database transactions carefully to ensure data consistency while avoiding deadlocks and performance issues.
</guideline>

<examples>
<example>
<situation>Implementing complex transactional operations</situation>
<recommended>
```typescript
@Injectable()
export class OrderService {
  constructor(
    private dataSource: DataSource,
    private inventoryService: InventoryService,
    private paymentService: PaymentService,
    private eventBus: EventBus
  ) {}

  async createOrder(dto: CreateOrderDto): Promise<Order> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction('SERIALIZABLE');

    try {
      // 1. Reserve inventory within transaction
      const reservations = await this.reserveInventory(
        dto.items,
        queryRunner.manager
      );

      // 2. Create order
      const order = queryRunner.manager.create(Order, {
        userId: dto.userId,
        items: dto.items,
        totalAmount: this.calculateTotal(dto.items),
        status: OrderStatus.PENDING,
      });
      await queryRunner.manager.save(order);

      // 3. Create order items
      const orderItems = dto.items.map(item =>
        queryRunner.manager.create(OrderItem, {
          orderId: order.id,
          productId: item.productId,
          quantity: item.quantity,
          price: item.price,
          reservationId: reservations.get(item.productId),
        })
      );
      await queryRunner.manager.save(orderItems);

      // 4. Process payment (idempotent)
      const payment = await this.paymentService.processPayment({
        orderId: order.id,
        amount: order.totalAmount,
        idempotencyKey: `order-${order.id}`,
      });

      // 5. Update order status
      order.status = OrderStatus.CONFIRMED;
      order.paymentId = payment.id;
      await queryRunner.manager.save(order);

      // Commit transaction
      await queryRunner.commitTransaction();

      // 6. Publish events after successful commit
      await this.eventBus.publish(new OrderCreatedEvent(order));

      return order;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      
      // Compensate for any external actions
      if (error.code === 'INSUFFICIENT_INVENTORY') {
        throw new BadRequestException('Insufficient inventory');
      }
      
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Saga pattern for distributed transactions
  async processOrderSaga(orderId: string): Promise<void> {
    const saga = new OrderProcessingSaga(orderId);
    
    try {
      // Step 1: Reserve inventory
      await saga.execute(async () => {
        await this.inventoryService.reserve(orderId);
      }, async () => {
        await this.inventoryService.release(orderId);
      });

      // Step 2: Process payment
      await saga.execute(async () => {
        await this.paymentService.charge(orderId);
      }, async () => {
        await this.paymentService.refund(orderId);
      });

      // Step 3: Fulfill order
      await saga.execute(async () => {
        await this.fulfillmentService.createShipment(orderId);
      }, async () => {
        await this.fulfillmentService.cancelShipment(orderId);
      });

      await saga.complete();
    } catch (error) {
      await saga.compensate();
      throw error;
    }
  }
}
```
</recommended>
</example>
</examples>

## Security Architecture

### Authentication and Authorization

<guideline>
Implement robust authentication and authorization systems. Never trust client input and always validate permissions at the service layer.
</guideline>

<examples>
<example>
<situation>Building a secure authentication system with JWT and refresh tokens</situation>
<recommended>
```typescript
// Secure authentication service
@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private tokenService: TokenService,
    private redis: RedisService,
    private config: ConfigService
  ) {}

  async login(dto: LoginDto): Promise<AuthResponse> {
    // Rate limiting per IP
    await this.checkRateLimit(dto.ipAddress);

    const user = await this.userService.findByEmail(dto.email);
    if (!user || !await this.verifyPassword(dto.password, user.password)) {
      // Consistent timing to prevent timing attacks
      await this.simulateHashDelay();
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check account status
    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException('Account is not active');
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokenPair(user);
    
    // Store refresh token with metadata
    await this.storeRefreshToken(refreshToken, user.id, dto);

    // Audit log
    await this.auditLog.record({
      action: 'LOGIN',
      userId: user.id,
      ipAddress: dto.ipAddress,
      userAgent: dto.userAgent,
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: this.config.get('auth.accessTokenTTL'),
    };
  }

  private async generateTokenPair(user: User): Promise<TokenPair> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: await this.resolvePermissions(user),
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccess(payload),
      this.tokenService.signRefresh({ sub: user.id }),
    ]);

    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string): Promise<AuthResponse> {
    const payload = await this.tokenService.verifyRefresh(refreshToken);
    
    // Validate stored token
    const storedToken = await this.redis.get(`refresh:${payload.jti}`);
    if (!storedToken || storedToken !== refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if token is blacklisted
    if (await this.isTokenBlacklisted(refreshToken)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    const user = await this.userService.findById(payload.sub);
    if (!user || user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Rotate refresh token
    const newTokens = await this.generateTokenPair(user);
    
    // Invalidate old token
    await this.invalidateRefreshToken(refreshToken);
    
    // Store new token
    await this.storeRefreshToken(newTokens.refreshToken, user.id);

    return {
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
      expiresIn: this.config.get('auth.accessTokenTTL'),
    };
  }

  private async verifyPassword(
    plainPassword: string,
    hashedPassword: string
  ): Promise<boolean> {
    return argon2.verify(hashedPassword, plainPassword, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
  }
}

// Authorization guard with permission checking
@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private authService: AuthService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<string[]>(
      'permissions',
      context.getHandler()
    );

    if (!requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      return false;
    }

    // Check permissions
    const userPermissions = await this.authService.getUserPermissions(user.id);
    
    return requiredPermissions.every(permission =>
      userPermissions.includes(permission)
    );
  }
}

// Resource-based authorization
@Injectable()
export class ResourceAuthService {
  async canAccess(
    user: User,
    resource: Resource,
    action: Action
  ): Promise<boolean> {
    // Check ownership
    if (resource.ownerId === user.id) {
      return true;
    }

    // Check team membership
    if (resource.teamId) {
      const membership = await this.teamService.getMembership(
        user.id,
        resource.teamId
      );
      
      if (membership && this.hasPermission(membership.role, action)) {
        return true;
      }
    }

    // Check global permissions
    return this.hasGlobalPermission(user, resource.type, action);
  }
}
```
</recommended>
</example>
</examples>

### Input Validation and Sanitization

<guideline>
Validate and sanitize all input at the edge of your system. Use strong typing and validation libraries to ensure data integrity.
</guideline>

<examples>
<example>
<situation>Implementing comprehensive input validation</situation>
<recommended>
```typescript
// DTO with comprehensive validation
export class CreateUserDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @Transform(({ value }) => value.toLowerCase().trim())
  email: string;

  @IsStrongPassword({
    minLength: 12,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })
  @IsNotEmpty()
  password: string;

  @IsString()
  @Length(2, 100)
  @Matches(/^[a-zA-Z\s\-']+$/, {
    message: 'Name contains invalid characters',
  })
  @Transform(({ value }) => sanitizeHtml(value.trim()))
  fullName: string;

  @IsOptional()
  @IsPhoneNumber()
  phoneNumber?: string;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => UserPreferencesDto)
  preferences?: UserPreferencesDto;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(10)
  @IsEnum(UserRole, { each: true })
  roles?: UserRole[];
}

// Custom validators for complex logic
@ValidatorConstraint({ async: true })
export class IsUniqueEmailConstraint implements ValidatorConstraintInterface {
  constructor(private userService: UserService) {}

  async validate(email: string): Promise<boolean> {
    const user = await this.userService.findByEmail(email);
    return !user;
  }

  defaultMessage(): string {
    return 'Email $value already exists';
  }
}

// SQL injection prevention
@Injectable()
export class QueryValidator {
  validateSearchQuery(query: string): string {
    // Remove SQL keywords and special characters
    const sanitized = query
      .replace(/[;'"\\]/g, '')
      .replace(/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b/gi, '')
      .trim();

    if (sanitized.length > 100) {
      throw new BadRequestException('Search query too long');
    }

    return sanitized;
  }

  validateSortField(field: string, allowedFields: string[]): string {
    if (!allowedFields.includes(field)) {
      throw new BadRequestException(`Invalid sort field: ${field}`);
    }
    return field;
  }
}

// File upload validation
@Injectable()
export class FileValidationService {
  private readonly allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'image/webp',
    'application/pdf',
  ];

  private readonly maxFileSize = 10 * 1024 * 1024; // 10MB

  async validateFile(file: Express.Multer.File): Promise<void> {
    // Check file size
    if (file.size > this.maxFileSize) {
      throw new BadRequestException('File too large');
    }

    // Verify MIME type
    const fileType = await fileTypeFromBuffer(file.buffer);
    if (!fileType || !this.allowedMimeTypes.includes(fileType.mime)) {
      throw new BadRequestException('Invalid file type');
    }

    // Scan for malware (example with ClamAV)
    const scanResult = await this.antivirusService.scan(file.buffer);
    if (scanResult.infected) {
      throw new BadRequestException('File contains malware');
    }

    // Additional image validation
    if (fileType.mime.startsWith('image/')) {
      await this.validateImage(file);
    }
  }

  private async validateImage(file: Express.Multer.File): Promise<void> {
    const metadata = await sharp(file.buffer).metadata();
    
    if (metadata.width > 4096 || metadata.height > 4096) {
      throw new BadRequestException('Image dimensions too large');
    }

    // Check for image bombs
    const pixelCount = metadata.width * metadata.height;
    const compressionRatio = file.size / pixelCount;
    
    if (compressionRatio < 0.01) {
      throw new BadRequestException('Suspicious image compression ratio');
    }
  }
}
```
</recommended>
</example>
</examples>

## Performance Optimization

### Caching Strategies

<guideline>
Implement multi-layer caching strategies to reduce database load and improve response times. Use appropriate cache invalidation strategies.
</guideline>

<examples>
<example>
<situation>Building a comprehensive caching system</situation>
<recommended>
```typescript
// Multi-layer cache implementation
@Injectable()
export class CacheService {
  private localCache = new LRUCache<string, any>({
    max: 1000,
    ttl: 1000 * 60 * 5, // 5 minutes
  });

  constructor(
    private redis: RedisService,
    private config: ConfigService
  ) {}

  async get<T>(
    key: string,
    factory: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    // L1 Cache - Local memory
    const localValue = this.localCache.get(key);
    if (localValue !== undefined) {
      return localValue;
    }

    // L2 Cache - Redis
    const redisValue = await this.redis.get(key);
    if (redisValue) {
      const parsed = JSON.parse(redisValue);
      this.localCache.set(key, parsed);
      return parsed;
    }

    // Cache miss - fetch from source
    const value = await factory();
    
    // Store in both caches
    await this.set(key, value, options);
    
    return value;
  }

  async set(
    key: string,
    value: any,
    options: CacheOptions = {}
  ): Promise<void> {
    const ttl = options.ttl || this.config.get('cache.defaultTTL');
    
    // Store in Redis with TTL
    await this.redis.setex(
      key,
      ttl,
      JSON.stringify(value)
    );

    // Store in local cache
    this.localCache.set(key, value);

    // Set up auto-refresh if needed
    if (options.autoRefresh) {
      this.scheduleRefresh(key, options.factory, ttl);
    }
  }

  async invalidate(pattern: string): Promise<void> {
    // Clear from local cache
    for (const [key] of this.localCache.entries()) {
      if (minimatch(key, pattern)) {
        this.localCache.delete(key);
      }
    }

    // Clear from Redis
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  // Cache-aside pattern with stampede protection
  async getWithLock<T>(
    key: string,
    factory: () => Promise<T>,
    ttl: number = 3600
  ): Promise<T> {
    const value = await this.get(key, null);
    if (value !== null) {
      return value;
    }

    // Acquire lock to prevent stampede
    const lockKey = `lock:${key}`;
    const lock = await this.redis.set(
      lockKey,
      '1',
      'NX',
      'EX',
      30
    );

    if (!lock) {
      // Another process is refreshing, wait and retry
      await this.delay(100);
      return this.getWithLock(key, factory, ttl);
    }

    try {
      const freshValue = await factory();
      await this.set(key, freshValue, { ttl });
      return freshValue;
    } finally {
      await this.redis.del(lockKey);
    }
  }
}

// Repository with caching
@Injectable()
export class CachedUserRepository {
  constructor(
    private userRepository: UserRepository,
    private cache: CacheService,
    private eventBus: EventBus
  ) {
    // Listen for cache invalidation events
    this.eventBus.subscribe(UserUpdatedEvent, (event) => {
      this.invalidateUser(event.userId);
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.cache.get(
      `user:${id}`,
      () => this.userRepository.findById(id),
      { ttl: 3600 }
    );
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.cache.get(
      `user:email:${email}`,
      () => this.userRepository.findByEmail(email),
      { ttl: 3600 }
    );
  }

  async save(user: User): Promise<User> {
    const saved = await this.userRepository.save(user);
    
    // Update cache
    await Promise.all([
      this.cache.set(`user:${saved.id}`, saved),
      this.cache.set(`user:email:${saved.email}`, saved),
    ]);

    // Publish event for cache invalidation
    await this.eventBus.publish(new UserUpdatedEvent(saved.id));

    return saved;
  }

  private async invalidateUser(userId: string): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (user) {
      await Promise.all([
        this.cache.invalidate(`user:${userId}`),
        this.cache.invalidate(`user:email:${user.email}`),
      ]);
    }
  }
}

// HTTP caching headers
@Injectable()
export class HttpCacheInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    return next.handle().pipe(
      tap((data) => {
        // Set cache headers based on endpoint
        const cacheConfig = this.getCacheConfig(request.route.path);
        
        if (cacheConfig.public) {
          response.setHeader(
            'Cache-Control',
            `public, max-age=${cacheConfig.maxAge}`
          );
        } else {
          response.setHeader(
            'Cache-Control',
            'private, no-cache, no-store, must-revalidate'
          );
        }

        // ETag support
        if (cacheConfig.etag && data) {
          const etag = this.generateETag(data);
          response.setHeader('ETag', etag);
          
          if (request.headers['if-none-match'] === etag) {
            response.status(304).end();
            return;
          }
        }
      })
    );
  }
}
```
</recommended>
</example>
</examples>

### Async Processing and Queue Management

<guideline>
Use message queues for heavy processing, ensure idempotency, and implement proper error handling with retry mechanisms.
</guideline>

<examples>
<example>
<situation>Implementing robust async job processing</situation>
<recommended>
```typescript
// Job queue configuration
@Injectable()
export class QueueService {
  private queues = new Map<string, Queue>();

  constructor(
    private redis: RedisService,
    private config: ConfigService
  ) {
    this.initializeQueues();
  }

  private initializeQueues(): void {
    const queueConfigs = [
      { name: 'email', concurrency: 10 },
      { name: 'image-processing', concurrency: 5 },
      { name: 'data-export', concurrency: 2 },
      { name: 'notifications', concurrency: 20 },
    ];

    for (const config of queueConfigs) {
      const queue = new Queue(config.name, {
        redis: this.redis.options,
        defaultJobOptions: {
          removeOnComplete: 100,
          removeOnFail: 1000,
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
        },
      });

      this.queues.set(config.name, queue);
      this.setupWorker(queue, config.concurrency);
    }
  }

  async addJob<T>(
    queueName: string,
    jobName: string,
    data: T,
    options: JobOptions = {}
  ): Promise<Job<T>> {
    const queue = this.queues.get(queueName);
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }

    // Add idempotency key if not provided
    const jobOptions: JobOptions = {
      ...options,
      jobId: options.jobId || this.generateJobId(queueName, jobName, data),
    };

    return queue.add(jobName, data, jobOptions);
  }

  private setupWorker(queue: Queue, concurrency: number): void {
    const worker = new Worker(
      queue.name,
      async (job) => {
        const processor = this.getProcessor(job.name);
        if (!processor) {
          throw new Error(`No processor for job ${job.name}`);
        }

        // Add context to job
        const context: JobContext = {
          jobId: job.id,
          attemptNumber: job.attemptsMade + 1,
          progress: (percent: number) => job.updateProgress(percent),
        };

        return processor.process(job.data, context);
      },
      {
        connection: this.redis.options,
        concurrency,
        limiter: {
          max: concurrency * 2,
          duration: 1000,
        },
      }
    );

    // Event handlers
    worker.on('completed', (job) => {
      this.logger.info(`Job ${job.id} completed`, {
        queue: queue.name,
        jobName: job.name,
        duration: Date.now() - job.timestamp,
      });
    });

    worker.on('failed', (job, err) => {
      this.logger.error(`Job ${job.id} failed`, {
        queue: queue.name,
        jobName: job.name,
        error: err.message,
        attemptsMade: job.attemptsMade,
      });

      // Send to DLQ if max attempts reached
      if (job.attemptsMade >= job.opts.attempts) {
        this.sendToDeadLetterQueue(job, err);
      }
    });
  }
}

// Job processor with idempotency
@Injectable()
@Processor('email')
export class EmailProcessor {
  constructor(
    private emailService: EmailService,
    private redis: RedisService
  ) {}

  @Process('send-welcome-email')
  async sendWelcomeEmail(job: Job<WelcomeEmailData>): Promise<void> {
    const { userId, email, name } = job.data;
    
    // Check idempotency
    const processedKey = `processed:welcome-email:${userId}`;
    const alreadyProcessed = await this.redis.get(processedKey);
    
    if (alreadyProcessed) {
      this.logger.info(`Welcome email already sent to ${userId}`);
      return;
    }

    try {
      // Process email
      await this.emailService.send({
        to: email,
        template: 'welcome',
        data: { name },
        trackingId: `welcome-${userId}`,
      });

      // Mark as processed
      await this.redis.setex(processedKey, 86400 * 7, '1'); // 7 days
      
      // Update progress
      await job.updateProgress(100);
    } catch (error) {
      // Check if error is retryable
      if (this.isRetryableError(error)) {
        throw error; // Will be retried
      }
      
      // Non-retryable error - mark as processed to prevent loops
      await this.redis.setex(processedKey, 86400, 'failed');
      throw new UnrecoverableError(error.message);
    }
  }

  @Process('send-bulk-email')
  async sendBulkEmail(job: Job<BulkEmailData>): Promise<void> {
    const { campaignId, recipients } = job.data;
    const batchSize = 100;
    
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      await Promise.all(
        batch.map(recipient =>
          this.sendCampaignEmail(campaignId, recipient)
            .catch(err => this.handleBatchError(err, recipient))
        )
      );
      
      // Update progress
      const progress = Math.round((i + batch.length) / recipients.length * 100);
      await job.updateProgress(progress);
      
      // Rate limiting
      await this.delay(1000);
    }
  }

  private isRetryableError(error: any): boolean {
    // Network errors, rate limits, etc.
    return (
      error.code === 'ECONNREFUSED' ||
      error.code === 'ETIMEDOUT' ||
      error.statusCode === 429 ||
      error.statusCode >= 500
    );
  }
}

// Circuit breaker for external services
@Injectable()
export class ExternalServiceClient {
  private circuitBreaker: CircuitBreaker;

  constructor(private httpService: HttpService) {
    this.circuitBreaker = new CircuitBreaker(
      (args: any) => this.makeRequest(args),
      {
        timeout: 5000,
        errorThresholdPercentage: 50,
        resetTimeout: 30000,
        rollingCountTimeout: 10000,
        rollingCountBuckets: 10,
      }
    );

    this.circuitBreaker.on('open', () => {
      this.logger.warn('Circuit breaker opened');
    });
  }

  async callExternalAPI(endpoint: string, data: any): Promise<any> {
    try {
      return await this.circuitBreaker.fire({ endpoint, data });
    } catch (error) {
      if (error.name === 'CircuitBreakerOpenError') {
        // Use fallback or cached data
        return this.getFallbackData(endpoint, data);
      }
      throw error;
    }
  }

  private async makeRequest({ endpoint, data }): Promise<any> {
    const response = await this.httpService.post(endpoint, data).toPromise();
    return response.data;
  }
}
```
</recommended>
</example>
</examples>

## Observability and Monitoring

### Structured Logging

<guideline>
Implement structured logging with correlation IDs for distributed tracing. Include contextual information for effective debugging.
</guideline>

<examples>
<example>
<situation>Building comprehensive logging and monitoring</situation>
<recommended>
```typescript
// Structured logger with context
@Injectable()
export class LoggerService {
  private logger: winston.Logger;

  constructor(private config: ConfigService) {
    this.logger = winston.createLogger({
      level: config.get('logging.level'),
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: {
        service: config.get('app.name'),
        environment: config.get('app.env'),
        version: config.get('app.version'),
      },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
        }),
        new winston.transports.File({
          filename: 'logs/error.log',
          level: 'error',
        }),
        new winston.transports.File({
          filename: 'logs/combined.log',
        }),
      ],
    });

    // Add DataDog transport in production
    if (config.get('app.env') === 'production') {
      this.addDataDogTransport();
    }
  }

  log(level: string, message: string, context?: any): void {
    this.logger.log(level, message, {
      ...context,
      timestamp: new Date().toISOString(),
    });
  }

  error(message: string, error?: Error, context?: any): void {
    this.logger.error(message, {
      ...context,
      error: {
        message: error?.message,
        stack: error?.stack,
        name: error?.name,
      },
    });
  }

  // Async context for request tracking
  async withContext<T>(
    context: LogContext,
    fn: () => Promise<T>
  ): Promise<T> {
    return AsyncLocalStorage.run(context, fn);
  }
}

// Request tracking middleware
@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  constructor(private logger: LoggerService) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const requestId = req.headers['x-request-id'] || uuidv4();
    const startTime = Date.now();

    // Add to request context
    req['requestId'] = requestId;
    req['context'] = {
      requestId,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    };

    // Log request
    this.logger.log('info', 'Incoming request', req['context']);

    // Log response
    const originalSend = res.send;
    res.send = function(data) {
      const duration = Date.now() - startTime;
      
      logger.log('info', 'Request completed', {
        ...req['context'],
        statusCode: res.statusCode,
        duration,
        contentLength: res.get('content-length'),
      });

      // Add request ID to response
      res.setHeader('X-Request-ID', requestId);
      
      return originalSend.call(this, data);
    };

    next();
  }
}

// Metrics collection
@Injectable()
export class MetricsService {
  private prometheus = client;
  private counters = new Map<string, Counter>();
  private histograms = new Map<string, Histogram>();
  private gauges = new Map<string, Gauge>();

  constructor() {
    this.initializeMetrics();
  }

  private initializeMetrics(): void {
    // HTTP metrics
    this.createHistogram('http_request_duration_seconds', {
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5],
    });

    // Business metrics
    this.createCounter('user_registrations_total', {
      help: 'Total number of user registrations',
      labelNames: ['source'],
    });

    this.createGauge('active_connections', {
      help: 'Number of active WebSocket connections',
    });

    // Database metrics
    this.createHistogram('database_query_duration_seconds', {
      help: 'Duration of database queries',
      labelNames: ['operation', 'table'],
    });

    // Queue metrics
    this.createGauge('queue_size', {
      help: 'Current size of job queues',
      labelNames: ['queue_name'],
    });
  }

  recordHttpRequest(
    method: string,
    route: string,
    statusCode: number,
    duration: number
  ): void {
    this.histograms
      .get('http_request_duration_seconds')
      .observe({ method, route, status_code: statusCode }, duration / 1000);
  }

  incrementUserRegistration(source: string): void {
    this.counters
      .get('user_registrations_total')
      .inc({ source });
  }

  async collectCustomMetrics(): Promise<void> {
    // Collect queue sizes
    const queues = await this.queueService.getQueueStats();
    for (const [name, size] of Object.entries(queues)) {
      this.gauges
        .get('queue_size')
        .set({ queue_name: name }, size);
    }

    // Collect active connections
    const connections = await this.wsService.getActiveConnections();
    this.gauges.get('active_connections').set(connections);
  }

  getMetrics(): Promise<string> {
    return this.prometheus.register.metrics();
  }
}

// Distributed tracing
@Injectable()
export class TracingService {
  private tracer: Tracer;

  constructor(config: ConfigService) {
    this.tracer = new Tracer({
      serviceName: config.get('app.name'),
      sampler: {
        type: 'probabilistic',
        param: config.get('tracing.samplingRate', 0.1),
      },
      reporter: {
        logSpans: false,
        agentHost: config.get('tracing.agentHost'),
        agentPort: config.get('tracing.agentPort'),
      },
    });
  }

  startSpan(name: string, parentSpan?: Span): Span {
    const options = parentSpan
      ? { childOf: parentSpan }
      : {};

    return this.tracer.startSpan(name, options);
  }

  async traceAsync<T>(
    name: string,
    fn: (span: Span) => Promise<T>,
    parentSpan?: Span
  ): Promise<T> {
    const span = this.startSpan(name, parentSpan);
    
    try {
      const result = await fn(span);
      span.finish();
      return result;
    } catch (error) {
      span.setTag('error', true);
      span.log({
        event: 'error',
        message: error.message,
        stack: error.stack,
      });
      span.finish();
      throw error;
    }
  }
}
```
</recommended>
</example>
</examples>

## Testing Strategies

### Unit and Integration Testing

<guideline>
Write tests that verify behavior, not implementation. Focus on integration tests for APIs and use unit tests for complex business logic.
</guideline>

<examples>
<example>
<situation>Comprehensive testing approach for backend services</situation>
<recommended>
```typescript
// Integration test for API endpoints
describe('UserController (e2e)', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let jwtToken: string;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ConfigService)
      .useValue(mockConfigService)
      .compile();

    app = moduleFixture.createNestApplication();
    
    // Apply same configuration as production
    app.useGlobalPipes(new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }));
    app.useGlobalFilters(new GlobalExceptionFilter());
    
    await app.init();
    
    dataSource = app.get(DataSource);
    
    // Setup test data
    await seedTestData(dataSource);
    jwtToken = await getAuthToken(app);
  });

  afterAll(async () => {
    await cleanupTestData(dataSource);
    await app.close();
  });

  describe('POST /users', () => {
    it('should create a new user with valid data', async () => {
      const createUserDto = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
        fullName: 'Test User',
        roles: ['user'],
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${jwtToken}`)
        .send(createUserDto)
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        email: createUserDto.email,
        fullName: createUserDto.fullName,
        roles: createUserDto.roles,
        createdAt: expect.any(String),
      });

      // Verify user was actually created
      const user = await dataSource
        .getRepository(User)
        .findOne({ where: { email: createUserDto.email } });
      
      expect(user).toBeDefined();
      expect(await argon2.verify(user.password, createUserDto.password)).toBe(true);
    });

    it('should reject duplicate email addresses', async () => {
      const existingUser = await createTestUser(dataSource);
      
      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${jwtToken}`)
        .send({
          email: existingUser.email,
          password: 'AnotherPassword123!',
          fullName: 'Another User',
        })
        .expect(409);

      expect(response.body).toMatchObject({
        error: {
          code: 'DUPLICATE_EMAIL',
          message: expect.stringContaining('already exists'),
        },
      });
    });

    it('should validate input data', async () => {
      const invalidData = {
        email: 'not-an-email',
        password: '123', // Too weak
        fullName: 'A', // Too short
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${jwtToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.error.details).toContainEqual(
        expect.objectContaining({
          field: 'email',
          message: expect.stringContaining('valid email'),
        })
      );
    });
  });

  describe('GET /users/:id', () => {
    it('should return user data for authorized requests', async () => {
      const user = await createTestUser(dataSource);
      
      const response = await request(app.getHttpServer())
        .get(`/users/${user.id}`)
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: user.id,
        email: user.email,
        fullName: user.fullName,
      });
      
      // Should not expose sensitive data
      expect(response.body).not.toHaveProperty('password');
    });

    it('should handle non-existent users', async () => {
      const response = await request(app.getHttpServer())
        .get(`/users/${uuidv4()}`)
        .set('Authorization', `Bearer ${jwtToken}`)
        .expect(404);

      expect(response.body.error.code).toBe('USER_NOT_FOUND');
    });

    it('should require authentication', async () => {
      const user = await createTestUser(dataSource);
      
      await request(app.getHttpServer())
        .get(`/users/${user.id}`)
        .expect(401);
    });
  });
});

// Service unit tests with mocking
describe('UserService', () => {
  let service: UserService;
  let repository: MockType<Repository<User>>;
  let eventBus: MockType<EventBus>;
  let cacheService: MockType<CacheService>;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(User),
          useFactory: repositoryMockFactory,
        },
        {
          provide: EventBus,
          useFactory: mockFactory<EventBus>(),
        },
        {
          provide: CacheService,
          useFactory: mockFactory<CacheService>(),
        },
      ],
    }).compile();

    service = module.get(UserService);
    repository = module.get(getRepositoryToken(User));
    eventBus = module.get(EventBus);
    cacheService = module.get(CacheService);
  });

  describe('createUser', () => {
    it('should create user and publish event', async () => {
      const createDto = {
        email: 'test@example.com',
        password: 'password',
        fullName: 'Test User',
      };

      const mockUser = {
        id: 'user-id',
        ...createDto,
        password: 'hashed-password',
      };

      repository.findOne.mockResolvedValue(null);
      repository.save.mockResolvedValue(mockUser);
      
      const result = await service.createUser(createDto);
      
      expect(repository.findOne).toHaveBeenCalledWith({
        where: { email: createDto.email },
      });
      
      expect(repository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          email: createDto.email,
          fullName: createDto.fullName,
          password: expect.not.stringMatching(createDto.password),
        })
      );
      
      expect(eventBus.publish).toHaveBeenCalledWith(
        expect.any(UserCreatedEvent)
      );
      
      expect(result).toEqual(mockUser);
    });

    it('should throw on duplicate email', async () => {
      repository.findOne.mockResolvedValue({ id: 'existing-user' });
      
      await expect(
        service.createUser({
          email: 'existing@example.com',
          password: 'password',
          fullName: 'Test',
        })
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('findById with caching', () => {
    it('should return cached user if available', async () => {
      const userId = 'user-id';
      const cachedUser = { id: userId, email: 'cached@example.com' };
      
      cacheService.get.mockResolvedValue(cachedUser);
      
      const result = await service.findById(userId);
      
      expect(cacheService.get).toHaveBeenCalledWith(
        `user:${userId}`,
        expect.any(Function)
      );
      expect(repository.findOne).not.toHaveBeenCalled();
      expect(result).toEqual(cachedUser);
    });

    it('should fetch from database on cache miss', async () => {
      const userId = 'user-id';
      const dbUser = { id: userId, email: 'db@example.com' };
      
      cacheService.get.mockImplementation(async (key, factory) => {
        return factory();
      });
      repository.findOne.mockResolvedValue(dbUser);
      
      const result = await service.findById(userId);
      
      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: userId },
      });
      expect(result).toEqual(dbUser);
    });
  });
});

// Test utilities
export function createMockRepository<T>(): MockType<Repository<T>> {
  return {
    find: jest.fn(),
    findOne: jest.fn(),
    save: jest.fn(),
    remove: jest.fn(),
    create: jest.fn(),
    createQueryBuilder: jest.fn(() => ({
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      offset: jest.fn().mockReturnThis(),
      getManyAndCount: jest.fn(),
      getMany: jest.fn(),
      getOne: jest.fn(),
    })),
  };
}
```
</recommended>
</example>
</examples>

## Microservices and Communication

### Service Communication Patterns

<guideline>
Choose appropriate communication patterns based on use case. Use synchronous communication for immediate responses and asynchronous for decoupled operations.
</guideline>

<examples>
<example>
<situation>Implementing various microservice communication patterns</situation>
<recommended>
```typescript
// gRPC service definition
@GrpcService()
export class UserGrpcService implements IUserService {
  constructor(
    private userService: UserService,
    private logger: LoggerService
  ) {}

  @GrpcMethod('UserService', 'GetUser')
  async getUser(data: GetUserRequest, metadata: Metadata): Promise<User> {
    const requestId = metadata.get('x-request-id')[0] || uuidv4();
    
    this.logger.log('info', 'gRPC GetUser request', {
      requestId,
      userId: data.id,
    });

    try {
      const user = await this.userService.findById(data.id);
      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: `User ${data.id} not found`,
        });
      }

      return this.mapToProto(user);
    } catch (error) {
      this.logger.error('gRPC GetUser error', error, { requestId });
      
      if (error instanceof RpcException) {
        throw error;
      }
      
      throw new RpcException({
        code: status.INTERNAL,
        message: 'Internal server error',
      });
    }
  }

  @GrpcStreamMethod('UserService', 'StreamUsers')
  streamUsers(data$: Observable<StreamUsersRequest>): Observable<User> {
    return data$.pipe(
      mergeMap(async (request) => {
        const users = await this.userService.findByIds(request.ids);
        return users;
      }),
      map(user => this.mapToProto(user)),
      catchError(error => {
        this.logger.error('Stream error', error);
        throw new RpcException({
          code: status.INTERNAL,
          message: error.message,
        });
      }),
    );
  }
}

// Event-driven communication
@Injectable()
export class EventPublisher {
  constructor(
    private kafka: KafkaService,
    private config: ConfigService
  ) {}

  async publish<T extends DomainEvent>(
    event: T,
    options: PublishOptions = {}
  ): Promise<void> {
    const topic = options.topic || this.getTopicForEvent(event);
    const key = options.key || event.aggregateId;
    
    const message = {
      key,
      value: JSON.stringify({
        eventId: event.id,
        eventType: event.constructor.name,
        aggregateId: event.aggregateId,
        payload: event.payload,
        metadata: {
          timestamp: event.timestamp,
          version: event.version,
          correlationId: event.correlationId,
          causationId: event.causationId,
        },
      }),
      headers: {
        'content-type': 'application/json',
        'event-type': event.constructor.name,
      },
    };

    await this.kafka.send({
      topic,
      messages: [message],
      acks: options.acks || 1,
      timeout: options.timeout || 5000,
    });
  }

  async publishBatch<T extends DomainEvent>(
    events: T[],
    options: BatchPublishOptions = {}
  ): Promise<void> {
    const messagesByTopic = new Map<string, any[]>();
    
    for (const event of events) {
      const topic = this.getTopicForEvent(event);
      if (!messagesByTopic.has(topic)) {
        messagesByTopic.set(topic, []);
      }
      
      messagesByTopic.get(topic).push({
        key: event.aggregateId,
        value: JSON.stringify(event),
      });
    }

    const promises = Array.from(messagesByTopic.entries()).map(
      ([topic, messages]) =>
        this.kafka.send({
          topic,
          messages,
          acks: options.acks || 1,
        })
    );

    await Promise.all(promises);
  }
}

// Event consumer with error handling
@Injectable()
export class EventConsumer {
  constructor(
    private kafka: KafkaService,
    private eventHandlers: EventHandlerRegistry,
    private logger: LoggerService
  ) {}

  async start(): Promise<void> {
    await this.kafka.subscribe({
      topics: this.config.get('kafka.topics'),
      fromBeginning: false,
    });

    await this.kafka.run({
      eachMessage: async ({ topic, partition, message }) => {
        const span = this.tracer.startSpan('process-message');
        
        try {
          await this.processMessage(message, { topic, partition });
          await this.commitOffset(topic, partition, message.offset);
          span.finish();
        } catch (error) {
          span.setTag('error', true);
          span.finish();
          
          await this.handleError(error, message, { topic, partition });
        }
      },
    });
  }

  private async processMessage(
    message: KafkaMessage,
    context: MessageContext
  ): Promise<void> {
    const event = this.parseMessage(message);
    const handlers = this.eventHandlers.getHandlers(event.eventType);
    
    if (handlers.length === 0) {
      this.logger.warn('No handlers for event type', {
        eventType: event.eventType,
        eventId: event.eventId,
      });
      return;
    }

    // Process handlers in parallel
    await Promise.all(
      handlers.map(handler =>
        this.executeHandler(handler, event, context)
          .catch(error => this.handleHandlerError(error, handler, event))
      )
    );
  }

  private async executeHandler(
    handler: EventHandler,
    event: DomainEvent,
    context: MessageContext
  ): Promise<void> {
    const startTime = Date.now();
    
    try {
      await handler.handle(event, context);
      
      this.metrics.recordEventProcessed({
        eventType: event.eventType,
        handler: handler.constructor.name,
        duration: Date.now() - startTime,
        success: true,
      });
    } catch (error) {
      this.metrics.recordEventProcessed({
        eventType: event.eventType,
        handler: handler.constructor.name,
        duration: Date.now() - startTime,
        success: false,
      });
      
      throw error;
    }
  }

  private async handleError(
    error: Error,
    message: KafkaMessage,
    context: MessageContext
  ): Promise<void> {
    const retryCount = this.getRetryCount(message);
    const maxRetries = this.config.get('kafka.maxRetries');
    
    if (retryCount < maxRetries && this.isRetryableError(error)) {
      await this.retryMessage(message, context, retryCount + 1);
    } else {
      await this.sendToDeadLetterQueue(message, error, context);
    }
  }
}

// HTTP client with resilience patterns
@Injectable()
export class ResilientHttpClient {
  private circuitBreakers = new Map<string, CircuitBreaker>();

  constructor(
    private httpService: HttpService,
    private config: ConfigService,
    private metrics: MetricsService
  ) {}

  async get<T>(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<T> {
    return this.executeWithResilience('GET', url, options);
  }

  async post<T>(
    url: string,
    data: any,
    options: HttpRequestOptions = {}
  ): Promise<T> {
    return this.executeWithResilience('POST', url, { ...options, data });
  }

  private async executeWithResilience<T>(
    method: string,
    url: string,
    options: HttpRequestOptions
  ): Promise<T> {
    const serviceName = this.getServiceName(url);
    const circuitBreaker = this.getCircuitBreaker(serviceName);
    
    try {
      return await circuitBreaker.fire(async () => {
        const response = await this.executeRequest(method, url, options);
        return response.data;
      });
    } catch (error) {
      if (error.name === 'CircuitBreakerOpenError') {
        this.metrics.incrementCounter('circuit_breaker_open', {
          service: serviceName,
        });
        
        // Try fallback
        if (options.fallback) {
          return options.fallback();
        }
      }
      
      throw error;
    }
  }

  private async executeRequest(
    method: string,
    url: string,
    options: HttpRequestOptions
  ): Promise<AxiosResponse> {
    const config: AxiosRequestConfig = {
      method,
      url,
      timeout: options.timeout || 5000,
      headers: {
        ...options.headers,
        'X-Request-ID': options.requestId || uuidv4(),
      },
      data: options.data,
    };

    // Add retry logic
    const axiosInstance = axios.create();
    axiosRetry(axiosInstance, {
      retries: options.retries || 3,
      retryDelay: axiosRetry.exponentialDelay,
      retryCondition: (error) => {
        return (
          axiosRetry.isNetworkOrIdempotentRequestError(error) ||
          error.response?.status === 429 ||
          error.response?.status >= 500
        );
      },
    });

    const startTime = Date.now();
    
    try {
      const response = await axiosInstance.request(config);
      
      this.metrics.recordHttpRequest({
        method,
        url,
        statusCode: response.status,
        duration: Date.now() - startTime,
        success: true,
      });
      
      return response;
    } catch (error) {
      this.metrics.recordHttpRequest({
        method,
        url,
        statusCode: error.response?.status || 0,
        duration: Date.now() - startTime,
        success: false,
      });
      
      throw error;
    }
  }

  private getCircuitBreaker(serviceName: string): CircuitBreaker {
    if (!this.circuitBreakers.has(serviceName)) {
      const breaker = new CircuitBreaker(
        (fn: Function) => fn(),
        {
          timeout: 10000,
          errorThresholdPercentage: 50,
          resetTimeout: 30000,
          rollingCountTimeout: 10000,
          rollingCountBuckets: 10,
          name: serviceName,
        }
      );
      
      this.circuitBreakers.set(serviceName, breaker);
    }
    
    return this.circuitBreakers.get(serviceName);
  }
}
```
</recommended>
</example>
</examples>

## Infrastructure as Code

### Container Orchestration

<guideline>
Design applications to be cloud-native and container-ready. Follow twelve-factor app principles and implement proper health checks.
</guideline>

<examples>
<example>
<situation>Creating production-ready Kubernetes deployments</situation>
<recommended>
```yaml
# Dockerfile with multi-stage build
FROM node:18-alpine AS builder

# Install dependencies for native modules
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock ./

# Install dependencies
RUN yarn install --frozen-lockfile

# Copy source code
COPY . .

# Build application
RUN yarn build

# Remove dev dependencies
RUN yarn install --production --frozen-lockfile

# Production image
FROM node:18-alpine

# Add non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./package.json

# Set environment
ENV NODE_ENV=production
ENV PORT=3000

# Expose port
EXPOSE 3000

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node healthcheck.js

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
```

```typescript
// Health check implementation
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private redis: RedisHealthIndicator,
    private kafka: KafkaHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      // Database health
      () => this.db.pingCheck('database', { timeout: 3000 }),
      
      // Redis health
      () => this.redis.pingCheck('redis', { timeout: 3000 }),
      
      // Kafka health
      () => this.kafka.pingCheck('kafka', { timeout: 3000 }),
      
      // Custom checks
      () => this.checkDiskSpace(),
      () => this.checkMemoryUsage(),
      () => this.checkExternalAPIs(),
    ]);
  }

  @Get('live')
  liveness() {
    // Simple liveness check - is the process running?
    return { status: 'ok' };
  }

  @Get('ready')
  async readiness() {
    // Readiness check - can we handle traffic?
    try {
      await this.db.pingCheck('database', { timeout: 1000 });
      return { status: 'ready' };
    } catch (error) {
      throw new ServiceUnavailableException('Service not ready');
    }
  }

  private async checkDiskSpace(): Promise<HealthIndicatorResult> {
    const disk = await checkDiskSpace('/');
    const percentUsed = (disk.used / disk.total) * 100;
    
    const isHealthy = percentUsed < 90;
    
    return {
      disk: {
        status: isHealthy ? 'up' : 'down',
        used: disk.used,
        total: disk.total,
        percentUsed,
      },
    };
  }

  private async checkMemoryUsage(): Promise<HealthIndicatorResult> {
    const usage = process.memoryUsage();
    const limit = process.env.MEMORY_LIMIT 
      ? parseInt(process.env.MEMORY_LIMIT) 
      : 512 * 1024 * 1024; // 512MB default
    
    const percentUsed = (usage.heapUsed / limit) * 100;
    const isHealthy = percentUsed < 85;
    
    return {
      memory: {
        status: isHealthy ? 'up' : 'down',
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        limit,
        percentUsed,
      },
    };
  }
}
```

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
  namespace: production
  labels:
    app: api-service
    version: v1
spec:
  replicas: 3
  revisionHistoryLimit: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: api-service
  template:
    metadata:
      labels:
        app: api-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "3000"
        prometheus.io/path: "/metrics"
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - api-service
              topologyKey: kubernetes.io/hostname
      
      containers:
      - name: api-service
        image: registry.example.com/api-service:1.2.3
        imagePullPolicy: Always
        
        ports:
        - name: http
          containerPort: 3000
          protocol: TCP
        
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3000"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: redis-url
        
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        
        livenessProbe:
          httpGet:
            path: /health/live
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: http
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 15"]
        
        securityContext:
          runAsNonRoot: true
          runAsUser: 1001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/.cache
      
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
      
      serviceAccountName: api-service
      securityContext:
        fsGroup: 1001

---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-service-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 2
        periodSeconds: 60

---
# Pod Disruption Budget
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-service-pdb
  namespace: production
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: api-service
```
</recommended>
</example>
</examples>

## Conclusion

<summary>
These guidelines represent current best practices for building modern backend applications. They emphasize reliability, security, performance, and maintainability as core requirements throughout the development lifecycle.
</summary>

<key_principles>
1. **Design for failure** - Build resilient systems that handle errors gracefully
2. **Security by default** - Never trust external input and validate everything
3. **Observable systems** - Comprehensive logging, monitoring, and tracing
4. **Performance at scale** - Design with growth in mind from day one
5. **API-first approach** - Clear contracts before implementation
6. **Automate everything** - From testing to deployment
</key_principles>

<continuous_improvement>
Review and update these guidelines quarterly to incorporate:
- New security threats and mitigations
- Performance optimization techniques
- Cloud-native patterns and practices
- Team learnings and post-mortems
- Industry best practices evolution
</continuous_improvement>

<thinking>
Remember: The best backend systems are those that users never notice - they just work reliably, securely, and efficiently. These guidelines should enable building such invisible excellence.
</thinking>