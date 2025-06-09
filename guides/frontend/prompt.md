# Frontend Design Guidelines v1.0

<role>
You are a principal frontend architect with 15+ years of experience building scalable React applications. You specialize in creating maintainable, performant, and accessible web applications following industry best practices.
</role>

<context>
This comprehensive guide serves as the authoritative reference for frontend development standards. It will be used by:
- Junior developers learning best practices
- Senior developers ensuring consistency
- Tech leads making architectural decisions
- Code reviewers maintaining quality standards

The guidelines must be immediately actionable with concrete examples.
</context>

<objectives>
1. Establish clear, enforceable coding standards
2. Provide practical patterns with real-world examples
3. Ensure accessibility and performance are built-in, not bolted-on
4. Create a living document that evolves with the ecosystem
</objectives>

<thinking>
The guidelines should balance prescriptive rules with flexibility for context-specific decisions. Each principle needs clear rationale and multiple examples showing both recommended and discouraged patterns.
</thinking>

<constraints>
- Prioritize code clarity over cleverness
- Always consider bundle size impact
- Ensure cross-browser compatibility
- Maintain backward compatibility when possible
</constraints>

## Core Principles

<principles>
1. **Write self-documenting code** - Code should clearly express intent without excessive comments
2. **Maintain consistency** - Follow established patterns throughout the codebase
3. **Build for all users** - Accessibility and performance are fundamental requirements
4. **Test what users experience** - Focus testing on behavior, not implementation
5. **Optimize based on data** - Measure performance before optimizing
</principles>

## Language Standards

<instructions>
All code artifacts including comments, documentation, variable names, and commit messages must use English. This ensures global team collaboration and maintains consistency with the broader development ecosystem.
</instructions>

## Code Organization and Readability

### Self-Documenting Code

<guideline>
Write code that clearly expresses its purpose through meaningful names and logical structure. Add comments only when explaining complex business logic or historical decisions.
</guideline>

<examples>
<example>
<situation>Implementing discount calculation with business rules</situation>
<thinking>
The code should clearly express business logic through meaningful names and structure. Constants should be defined at the top for easy modification, and functions should have single responsibilities.
</thinking>
<recommended>
```typescript
// Business rule: Q2 2024 promotional campaign
// Gold tier customers with loyalty bonus receive additional benefits
const LOYALTY_THRESHOLD = 10;
const GOLD_TIER_DISCOUNT = 0.25;
const STANDARD_TIER_DISCOUNTS = {
  silver: 0.15,
  bronze: 0.10,
  basic: 0.05
};

function calculateCustomerDiscount(customer: Customer, orderAmount: number): number {
  if (isEligibleForLoyaltyBonus(customer)) {
    return orderAmount * GOLD_TIER_DISCOUNT;
  }
  
  return orderAmount * (STANDARD_TIER_DISCOUNTS[customer.tier] || 0);
}

function isEligibleForLoyaltyBonus(customer: Customer): boolean {
  return customer.tier === 'gold' && customer.purchaseCount >= LOYALTY_THRESHOLD;
}
```
</recommended>

<discouraged>
```typescript
// Calculate discount
function calc(c, amt) {
  // Check if gold
  if (c.t === 'gold' && c.pc >= 10) {
    return amt * 0.25; // 25% off
  }
  // Other tiers
  return amt * getDisc(c.t);
}
```
</discouraged>

<explanation>
The recommended approach uses descriptive names, extracts magic numbers into constants, and separates concerns into focused functions. This makes the business logic explicit and maintainable.
</explanation>
</example>
</examples>

### Component Structure Patterns

<guideline>
Organize components following the separation of concerns principle. Business logic belongs in hooks and services, UI logic in components, and cross-cutting concerns in context providers.
</guideline>

<examples>
<example>
<situation>User authentication flow with protected routes</situation>
<recommended>
```tsx
// Clear separation: Each component has a single responsibility

// 1. Authentication context manages auth state
export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const auth = useAuthService();
  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
};

// 2. Route guard handles access control
export const ProtectedRoute: React.FC<{ children: ReactNode; requiredRole?: Role }> = ({
  children,
  requiredRole
}) => {
  const { user, isLoading } = useAuth();
  
  if (isLoading) return <LoadingScreen />;
  if (!user) return <Navigate to="/login" />;
  if (requiredRole && !hasRole(user, requiredRole)) return <AccessDenied />;
  
  return <>{children}</>;
};

// 3. Login page focuses purely on UI
export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [formData, setFormData] = useState<LoginFormData>(initialFormData);
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await login(formData);
  };
  
  return (
    <form onSubmit={handleSubmit} className="login-form">
      <EmailInput
        value={formData.email}
        onChange={(email) => setFormData(prev => ({ ...prev, email }))}
      />
      <PasswordInput
        value={formData.password}
        onChange={(password) => setFormData(prev => ({ ...prev, password }))}
      />
      <SubmitButton>Sign In</SubmitButton>
    </form>
  );
};

```
</recommended>
</example>
</examples>

### Conditional Rendering Patterns

<guideline>
Express complex conditional logic through dedicated components or well-named functions. Use early returns to reduce nesting and improve readability.
</guideline>

<examples>
<example>
<situation>Role-based UI with different features per user type</situation>
<recommended>
```tsx
// Strategy pattern for role-specific components
const RoleComponents = {
  admin: AdminDashboard,
  manager: ManagerDashboard,
  employee: EmployeeDashboard,
  guest: GuestDashboard,
} as const;

export const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const Component = RoleComponents[user?.role || 'guest'];
  
  return <Component user={user} />;
};

// Each role component is focused and testable
const AdminDashboard: React.FC<{ user: User }> = ({ user }) => {
  const { data: analytics } = useAnalytics({ scope: 'company' });
  const { data: users } = useUsers();
  
  return (
    <DashboardLayout>
      <WelcomeHeader user={user} />
      <AnalyticsOverview data={analytics} />
      <UserManagementPanel users={users} />
      <SystemHealthMonitor />
    </DashboardLayout>
  );
};
```

</recommended>

<discouraged>
```tsx
// Avoid: Complex nested ternaries
const Dashboard = () => {
  const { user } = useAuth();
  
  return (
    <div>
      {user?.role === 'admin' ? (
        <div>
          <AdminPanel />
          {user.permissions.includes('analytics') ? <Analytics /> : null}
        </div>
      ) : user?.role === 'manager' ? (
        <ManagerView />
      ) : (
        <EmployeeView />
      )}
    </div>
  );
};

```
</discouraged>
</example>
</examples>

## TypeScript Excellence

### Type Safety Fundamentals

<guideline>
Leverage TypeScript's type system to catch errors at compile time. Define explicit types for all public APIs, use discriminated unions for state machines, and implement type guards for runtime validation.
</guideline>

<output_format>
When implementing TypeScript:
1. Always define explicit return types for functions
2. Use discriminated unions for state management
3. Implement proper type guards with is/as keywords
4. Leverage utility types (Partial, Pick, Omit, etc.)
5. Avoid any type except in exceptional cases with documentation
</output_format>

<examples>
<example>
<situation>API response handling with proper error management</situation>
<recommended>
```typescript
// Discriminated union for API states
type ApiState<T> = 
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T; timestamp: number }
  | { status: 'error'; error: ApiError; canRetry: boolean };

// Comprehensive error typing
interface ApiError {
  code: ErrorCode;
  message: string;
  details?: Record<string, unknown>;
  timestamp: number;
}

type ErrorCode = 
  | 'NETWORK_ERROR'
  | 'UNAUTHORIZED' 
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'VALIDATION_ERROR'
  | 'SERVER_ERROR'
  | 'UNKNOWN_ERROR';

// Type guard with proper narrowing
function isApiError(error: unknown): error is ApiError {
  return (
    error !== null &&
    typeof error === 'object' &&
    'code' in error &&
    'message' in error &&
    'timestamp' in error
  );
}

// Generic hook with full type safety
function useApiCall<T>(
  apiFunction: () => Promise<T>,
  options?: UseApiOptions
): UseApiResult<T> {
  const [state, setState] = useState<ApiState<T>>({ status: 'idle' });
  
  const execute = useCallback(async () => {
    setState({ status: 'loading' });
    
    try {
      const data = await apiFunction();
      setState({ 
        status: 'success', 
        data, 
        timestamp: Date.now() 
      });
      return data;
    } catch (error) {
      const apiError = normalizeError(error);
      setState({ 
        status: 'error', 
        error: apiError,
        canRetry: isRetryableError(apiError)
      });
      throw apiError;
    }
  }, [apiFunction]);
  
  return { state, execute };
}
```

</recommended>
</example>
</examples>

### Advanced Type Patterns

<guideline>
Use advanced TypeScript features to create robust, self-documenting APIs. Leverage mapped types, conditional types, and template literal types for maximum type safety.
</guideline>

<examples>
<example>
<situation>Building a type-safe form system</situation>
<recommended>
```typescript
// Form field configuration with full type inference
type FormFieldConfig<T> = {
  [K in keyof T]: {
    type: T[K] extends string ? 'text' | 'email' | 'password' :
          T[K] extends number ? 'number' :
          T[K] extends boolean ? 'checkbox' :
          T[K] extends Date ? 'date' : never;
    validate?: (value: T[K]) => string | undefined;
    transform?: (value: T[K]) => T[K];
    label: string;
    placeholder?: string;
    required?: boolean;
  }
};

// Usage with automatic type inference
interface UserFormData {
  name: string;
  email: string;
  age: number;
  acceptTerms: boolean;
  joinDate: Date;
}

const userFormConfig: FormFieldConfig<UserFormData> = {
  name: {
    type: 'text',
    label: 'Full Name',
    validate: (value) => value.length < 2 ? 'Name too short' : undefined,
    required: true,
  },
  email: {
    type: 'email',
    label: 'Email Address',
    validate: (value) => !isValidEmail(value) ? 'Invalid email' : undefined,
    required: true,
  },
  age: {
    type: 'number',
    label: 'Age',
    validate: (value) => value < 18 ? 'Must be 18 or older' : undefined,
  },
  acceptTerms: {
    type: 'checkbox',
    label: 'I accept the terms and conditions',
    required: true,
  },
  joinDate: {
    type: 'date',
    label: 'Join Date',
    transform: (value) => startOfDay(value),
  },
};

// Type-safe form hook
function useForm<T>(config: FormFieldConfig<T>, initialValues: T) {
  const [values, setValues] = useState<T>(initialValues);
  const [errors, setErrors] = useState<Partial<Record<keyof T, string>>>({});
  
  const setValue = <K extends keyof T>(field: K, value: T[K]) => {
    const fieldConfig = config[field];
    const transformedValue = fieldConfig.transform
      ? fieldConfig.transform(value)
      : value;

    setValues(prev => ({ ...prev, [field]: transformedValue }));
    
    // Validate on change
    const error = fieldConfig.validate?.(transformedValue);
    setErrors(prev => ({ ...prev, [field]: error }));
  };
  
  return { values, errors, setValue };
}

```
</recommended>
</example>
</examples>

## State Management Architecture

### State Management Decision Matrix

<state_strategy>
Choose the appropriate state management solution based on these criteria:

| Criteria | Local State | Context | Zustand | React Query | Redux |
|----------|------------|---------|---------|-------------|--------|
| Scope | Single component | Component tree | Global | Server state | Complex global |
| Complexity | Simple | Moderate | Moderate | N/A | High |
| Dev Experience | Excellent | Good | Excellent | Excellent | Moderate |
| Performance | Excellent | Good* | Excellent | Excellent | Good |
| Time Travel | No | No | Via middleware | No | Yes |
| DevTools | React DevTools | React DevTools | Custom | Excellent | Excellent |

*Context performance depends on proper optimization
</state_strategy>

<examples>
<example>
<situation>Implementing multi-source state management</situation>
<recommended>
```typescript
// 1. Server state with React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: (failureCount, error) => {
        if (error.status === 404) return false;
        return failureCount < 3;
      },
      refetchOnWindowFocus: false,
    },
  },
});

// 2. Global UI state with Zustand
interface UIStore {
  theme: 'light' | 'dark' | 'system';
  sidebarOpen: boolean;
  notifications: Notification[];
  setTheme: (theme: UIStore['theme']) => void;
  toggleSidebar: () => void;
  addNotification: (notification: Notification) => void;
  removeNotification: (id: string) => void;
}

const useUIStore = create<UIStore>((set) => ({
  theme: 'system',
  sidebarOpen: true,
  notifications: [],
  setTheme: (theme) => set({ theme }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  addNotification: (notification) => 
    set((state) => ({ 
      notifications: [...state.notifications, { ...notification, id: nanoid() }] 
    })),
  removeNotification: (id) =>
    set((state) => ({ 
      notifications: state.notifications.filter(n => n.id !== id) 
    })),
}));

// 3. Complex form state with reducer
type FormAction =
  | { type: 'SET_FIELD'; field: string; value: unknown }
  | { type: 'SET_ERRORS'; errors: Record<string, string> }
  | { type: 'RESET' }
  | { type: 'SUBMIT_START' }
  | { type: 'SUBMIT_SUCCESS' }
  | { type: 'SUBMIT_ERROR'; error: string };

function formReducer(state: FormState, action: FormAction): FormState {
  switch (action.type) {
    case 'SET_FIELD':
      return {
        ...state,
        values: { ...state.values, [action.field]: action.value },
        touched: { ...state.touched, [action.field]: true },
      };
    case 'SET_ERRORS':
      return { ...state, errors: action.errors };
    case 'SUBMIT_START':
      return { ...state, isSubmitting: true, submitError: null };
    case 'SUBMIT_SUCCESS':
      return { ...state, isSubmitting: false, isSubmitted: true };
    case 'SUBMIT_ERROR':
      return { ...state, isSubmitting: false, submitError: action.error };
    case 'RESET':
      return initialFormState;
    default:
      return state;
  }
}
```

</recommended>
</example>
</examples>

## Performance Optimization Strategies

### Performance Measurement First

<guideline>
Always measure before optimizing. Use React DevTools Profiler, Chrome DevTools, and real user metrics to identify actual bottlenecks.
</guideline>

<performance_workflow>

1. Establish performance budgets
2. Set up monitoring (Web Vitals, custom metrics)
3. Profile to identify bottlenecks
4. Optimize based on data
5. Verify improvements
6. Monitor continuously
</performance_workflow>

<examples>
<example>
<situation>Optimizing a data-heavy dashboard</situation>
<recommended>
```typescript
// Performance monitoring setup
const PerformanceMonitor: React.FC<{ children: ReactNode }> = ({ children }) => {
  useEffect(() => {
    // Web Vitals monitoring
    onCLS(metric => analytics.track('web-vital', { name: 'CLS', value: metric.value }));
    onFID(metric => analytics.track('web-vital', { name: 'FID', value: metric.value }));
    onLCP(metric => analytics.track('web-vital', { name: 'LCP', value: metric.value }));

    // Custom metrics
    performance.mark('app-interactive');
    const navigationEntry = performance.getEntriesByType('navigation')[0];
    if (navigationEntry) {
      analytics.track('app-performance', {
        dnsLookup: navigationEntry.domainLookupEnd - navigationEntry.domainLookupStart,
        tcpConnection: navigationEntry.connectEnd - navigationEntry.connectStart,
        request: navigationEntry.responseStart - navigationEntry.requestStart,
        response: navigationEntry.responseEnd - navigationEntry.responseStart,
        domProcessing: navigationEntry.domComplete - navigationEntry.domLoading,
        onLoad: navigationEntry.loadEventEnd - navigationEntry.loadEventStart,
      });
    }
  }, []);
  
  return <>{children}</>;
};

// Strategic memoization based on profiling data
const DataGrid = memo<DataGridProps>(({
  data,
  columns,
  onRowClick,
  filters,
  sorting
}) => {
  // Only recompute when data or filters change
  const processedData = useMemo(() => {
    console.time('DataProcessing');
    const filtered = applyFilters(data, filters);
    const sorted = applySorting(filtered, sorting);
    console.timeEnd('DataProcessing');
    return sorted;
  }, [data, filters, sorting]);
  
  // Virtualization for large datasets
  const rowVirtualizer = useVirtual({
    size: processedData.length,
    parentRef,
    estimateSize: useCallback(() => 50, []),
    overscan: 5,
  });
  
  return (
    <div ref={parentRef} className="data-grid">
      <div style={{ height: `${rowVirtualizer.totalSize}px` }}>
        {rowVirtualizer.virtualItems.map(virtualRow => (
          <DataRow
            key={processedData[virtualRow.index].id}
            data={processedData[virtualRow.index]}
            columns={columns}
            onClick={onRowClick}
            style={{
              transform: `translateY(${virtualRow.start}px)`,
            }}
          />
        ))}
      </div>
    </div>
  );
}, (prevProps, nextProps) => {
  // Custom comparison for expensive re-renders
  return (
    prevProps.data === nextProps.data &&
    deepEqual(prevProps.filters, nextProps.filters) &&
    deepEqual(prevProps.sorting, nextProps.sorting) &&
    prevProps.onRowClick === nextProps.onRowClick
  );
});

// Code splitting for heavy features
const AnalyticsPanel = lazy(() =>
  import(/*webpackChunkName: "analytics"*/ './AnalyticsPanel')
);

const Dashboard: React.FC = () => {
  const [showAnalytics, setShowAnalytics] = useState(false);
  
  return (
    <div className="dashboard">
      <DataGrid {...gridProps} />

      {showAnalytics && (
        <Suspense fallback={<AnalyticsSkeleton />}>
          <AnalyticsPanel />
        </Suspense>
      )}
    </div>
  );
};

```
</recommended>
</example>
</examples>

## Testing Excellence

### Testing Philosophy

<testing_principles>
Write tests that give confidence your application works for real users. Focus on behavior over implementation, integration over isolation, and user journeys over individual units.
</testing_principles>

<testing_pyramid>
Distribution for typical React applications:
- E2E Tests (10%): Critical user journeys
- Integration Tests (60%): Feature workflows  
- Unit Tests (30%): Business logic and utilities
</testing_pyramid>

<examples>
<example>
<situation>Testing a complete authentication flow</situation>
<recommended>
```typescript
// Integration test focusing on user experience
describe('Authentication Flow', () => {
  beforeEach(() => {
    // Reset all mocks and state
    cleanup();
    jest.clearAllMocks();
    window.localStorage.clear();
  });
  
  describe('Login Journey', () => {
    it('allows user to login and access protected content', async () => {
      // Arrange
      const user = userEvent.setup();
      server.use(
        rest.post('/api/auth/login', async (req, res, ctx) => {
          const { email, password } = await req.json();
          
          if (email === 'user@example.com' && password === 'password123') {
            return res(
              ctx.json({
                user: { id: '1', email, name: 'Test User' },
                token: 'mock-jwt-token',
              })
            );
          }
          
          return res(
            ctx.status(401),
            ctx.json({ error: 'Invalid credentials' })
          );
        })
      );
      
      // Act & Assert - Follow user journey
      const { container } = render(<App />);
      
      // User lands on home page
      expect(screen.getByRole('heading', { name: /welcome/i })).toBeInTheDocument();
      
      // User navigates to protected route
      await user.click(screen.getByRole('link', { name: /dashboard/i }));
      
      // User is redirected to login
      expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument();
      
      // User fills in credentials
      await user.type(screen.getByLabelText(/email/i), 'user@example.com');
      await user.type(screen.getByLabelText(/password/i), 'password123');
      
      // User submits form
      await user.click(screen.getByRole('button', { name: /sign in/i }));
      
      // User sees loading state
      expect(screen.getByText(/signing in/i)).toBeInTheDocument();
      
      // User is redirected to dashboard after successful login
      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /dashboard/i })).toBeInTheDocument();
      });
      
      // User info is displayed
      expect(screen.getByText(/test user/i)).toBeInTheDocument();
      
      // Auth token is stored
      expect(window.localStorage.getItem('auth-token')).toBe('mock-jwt-token');
    });
    
    it('shows error message for invalid credentials', async () => {
      const user = userEvent.setup();
      render(<App />);
      
      await user.click(screen.getByRole('link', { name: /dashboard/i }));
      await user.type(screen.getByLabelText(/email/i), 'wrong@example.com');
      await user.type(screen.getByLabelText(/password/i), 'wrongpassword');
      await user.click(screen.getByRole('button', { name: /sign in/i }));
      
      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent(/invalid credentials/i);
      });
      
      // User remains on login page
      expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument();
    });
  });
  
  describe('Session Management', () => {
    it('maintains session across page refreshes', async () => {
      // Setup authenticated state
      window.localStorage.setItem('auth-token', 'valid-token');
      server.use(
        rest.get('/api/auth/me', (req, res, ctx) => {
          const token = req.headers.get('Authorization');
          if (token === 'Bearer valid-token') {
            return res(ctx.json({ 
              user: { id: '1', email: 'user@example.com', name: 'Test User' } 
            }));
          }
          return res(ctx.status(401));
        })
      );
      
      // First render
      const { unmount } = render(<App />);
      
      // Wait for auth check
      await waitFor(() => {
        expect(screen.getByText(/test user/i)).toBeInTheDocument();
      });
      
      // Simulate page refresh
      unmount();
      render(<App />);
      
      // Session is maintained
      await waitFor(() => {
        expect(screen.getByText(/test user/i)).toBeInTheDocument();
      });
    });
  });
});

// Unit test for critical business logic
describe('Permission System', () => {
  describe('hasPermission', () => {
    const testCases = [
      {
        user: { role: 'admin', permissions: [] },
        permission: 'delete_user',
        resource: null,
        expected: true,
        description: 'admin has all permissions',
      },
      {
        user: { role: 'user', permissions: ['read_own_profile'] },
        permission: 'read_profile',
        resource: { ownerId: '123' },
        expected: false,
        description: 'user cannot read others profiles',
      },
      {
        user: { role: 'user', permissions: ['read_own_profile'], id: '123' },
        permission: 'read_profile',
        resource: { ownerId: '123' },
        expected: true,
        description: 'user can read own profile',
      },
    ];
    
    test.each(testCases)('$description', ({ user, permission, resource, expected }) => {
      expect(hasPermission(user, permission, resource)).toBe(expected);
    });
  });
});
```

</recommended>
</example>
</examples>

### Accessibility Testing

<guideline>
Include accessibility testing as a core part of your testing strategy. Test keyboard navigation, screen reader compatibility, and WCAG compliance.
</guideline>

<workflow>
Step 1 - AUDIT:
Run automated accessibility tools (axe, WAVE)
Document all violations and warnings

Step 2 - MANUAL TEST:
Test keyboard navigation flow
Verify screen reader announcements
Check color contrast ratios

Step 3 - FIX:
Address violations in order of severity
Implement proper ARIA attributes
Ensure focus management

Step 4 - VERIFY:
Re-run automated tests
Conduct user testing with assistive technologies
Document compliance status
</workflow>

<examples>
<example>
<situation>Testing modal accessibility comprehensively</situation>
<recommended>
```typescript
describe('Modal Accessibility', () => {
  it('meets WCAG 2.1 AA standards', async () => {
    const { container } = render(
      <Modal isOpen title="Confirm Delete" onClose={jest.fn()}>
        <p>Are you sure you want to delete this item?</p>
        <button>Cancel</button>
        <button>Delete</button>
      </Modal>
    );

    // Automated accessibility scan
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
  
  it('implements focus management correctly', async () => {
    const user = userEvent.setup();
    const onClose = jest.fn();

    render(
      <>
        <button>Outside button before</button>
        <Modal isOpen title="Test Modal" onClose={onClose}>
          <input type="text" placeholder="First input" />
          <button>Modal button</button>
          <a href="#">Modal link</a>
        </Modal>
        <button>Outside button after</button>
      </>
    );
    
    // Focus moves to first focusable element in modal
    expect(screen.getByPlaceholderText('First input')).toHaveFocus();
    
    // Tab cycles through modal elements only
    await user.tab();
    expect(screen.getByRole('button', { name: /modal button/i })).toHaveFocus();
    
    await user.tab();
    expect(screen.getByRole('link', { name: /modal link/i })).toHaveFocus();
    
    await user.tab();
    expect(screen.getByRole('button', { name: /close/i })).toHaveFocus();
    
    // Tab wraps to beginning
    await user.tab();
    expect(screen.getByPlaceholderText('First input')).toHaveFocus();
    
    // Escape closes modal
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });
  
  it('announces to screen readers correctly', () => {
    render(
      <Modal isOpen title="Important Announcement" onClose={jest.fn()}>
        <p>This is an important message.</p>
      </Modal>
    );

    const modal = screen.getByRole('dialog');
    
    // Proper ARIA attributes
    expect(modal).toHaveAttribute('aria-modal', 'true');
    expect(modal).toHaveAttribute('aria-labelledby');
    
    // Title is announced
    const title = screen.getByText('Important Announcement');
    expect(title).toHaveAttribute('id');
    expect(modal.getAttribute('aria-labelledby')).toBe(title.getAttribute('id'));
    
    // Live region for dynamic content
    const liveRegion = screen.getByRole('status');
    expect(liveRegion).toHaveAttribute('aria-live', 'polite');
  });
});

```
</recommended>
</example>
</examples>

## Error Handling Architecture

### Comprehensive Error Strategy

<error_handling_principles>
Every error should have a recovery path. Design for failure scenarios from the start, not as an afterthought. Provide meaningful feedback to users and detailed logs for developers.
</error_handling_principles>

<examples>
<example>
<situation>Building a resilient error handling system</situation>
<recommended>
```typescript
// Global error types and utilities
enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

interface AppError {
  code: string;
  message: string;
  severity: ErrorSeverity;
  context?: Record<string, unknown>;
  stack?: string;
  timestamp: number;
  retryable: boolean;
  userMessage?: string;
}

// Error boundary with telemetry
class GlobalErrorBoundary extends Component<
  { children: ReactNode },
  { error: AppError | null; errorId: string | null }
> {
  state = { error: null, errorId: null };
  
  static getDerivedStateFromError(error: Error): { error: AppError; errorId: string } {
    const errorId = generateErrorId();
    const appError = normalizeError(error);
    
    // Log to telemetry
    errorTelemetry.captureException(appError, {
      errorId,
      userAgent: navigator.userAgent,
      url: window.location.href,
      timestamp: Date.now(),
    });
    
    return { error: appError, errorId };
  }
  
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Additional logging with component stack
    console.error('Error Boundary Caught:', error, errorInfo);
  }
  
  render() {
    if (this.state.error) {
      return (
        <ErrorFallback
          error={this.state.error}
          errorId={this.state.errorId}
          onReset={() => this.setState({ error: null, errorId: null })}
        />
      );
    }
    
    return this.props.children;
  }
}

// User-friendly error display
const ErrorFallback: React.FC<{
  error: AppError;
  errorId: string | null;
  onReset: () => void;
}> = ({ error, errorId, onReset }) => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return (
    <div className="error-fallback">
      <div className="error-content">
        <h1>Something went wrong</h1>
        <p className="error-message">
          {error.userMessage || 'An unexpected error occurred. Please try again.'}
        </p>
        
        {errorId && (
          <p className="error-id">
            Error ID: <code>{errorId}</code>
          </p>
        )}
        
        <div className="error-actions">
          {error.retryable && (
            <button onClick={onReset} className="btn-primary">
              Try Again
            </button>
          )}
          <button onClick={() => window.location.href = '/'} className="btn-secondary">
            Go Home
          </button>
        </div>
        
        {!isProduction && (
          <details className="error-details">
            <summary>Technical Details</summary>
            <pre>{JSON.stringify(error, null, 2)}</pre>
            {error.stack && <pre>{error.stack}</pre>}
          </details>
        )}
      </div>
    </div>
  );
};

// Async error handling hook
function useAsyncError() {
  const [, setError] = useState();
  
  return useCallback((error: Error) => {
    setError(() => {
      throw error;
    });
  }, []);
}

// Network error recovery
const NetworkErrorBoundary: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [retryCount, setRetryCount] = useState(0);
  
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);
  
  if (!isOnline) {
    return (
      <div className="network-error">
        <h2>No Internet Connection</h2>
        <p>Please check your connection and try again.</p>
        <button 
          onClick={() => {
            setRetryCount(prev => prev + 1);
            window.location.reload();
          }}
        >
          Retry ({retryCount})
        </button>
      </div>
    );
  }
  
  return <>{children}</>;
};
```

</recommended>
</example>
</examples>

## Accessibility-First Development

### WCAG 2.1 Compliance

<accessibility_requirements>
Build applications that meet WCAG 2.1 Level AA standards as a minimum. Consider Level AAA for critical user journeys. Test with real assistive technologies and diverse users.
</accessibility_requirements>

<examples>
<example>
<situation>Building an accessible data table with sorting and filtering</situation>
<recommended>
```tsx
interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  caption: string;
  onSort?: (column: string, direction: 'asc' | 'desc') => void;
  onFilter?: (filters: FilterState) => void;
}

function DataTable<T extends Record<string, any>>({
  data,
  columns,
  caption,
  onSort,
  onFilter,
}: DataTableProps<T>) {
  const [sortState, setSortState] = useState<SortState>({ column: null, direction: null });
  const [announcement, setAnnouncement] = useState('');
  
  const handleSort = (column: string) => {
    const newDirection =
      sortState.column === column && sortState.direction === 'asc'
        ? 'desc'
        : 'asc';

    setSortState({ column, direction: newDirection });
    onSort?.(column, newDirection);
    
    // Announce sort change to screen readers
    setAnnouncement(
      `Table sorted by ${column} in ${newDirection}ending order`
    );
  };
  
  const handleKeyDown = (event: KeyboardEvent, rowIndex: number, colIndex: number) => {
    const { key } = event;
    let newRowIndex = rowIndex;
    let newColIndex = colIndex;

    switch (key) {
      case 'ArrowUp':
        newRowIndex = Math.max(0, rowIndex - 1);
        break;
      case 'ArrowDown':
        newRowIndex = Math.min(data.length - 1, rowIndex + 1);
        break;
      case 'ArrowLeft':
        newColIndex = Math.max(0, colIndex - 1);
        break;
      case 'ArrowRight':
        newColIndex = Math.min(columns.length - 1, colIndex + 1);
        break;
      case 'Home':
        newColIndex = 0;
        break;
      case 'End':
        newColIndex = columns.length - 1;
        break;
      default:
        return;
    }
    
    event.preventDefault();
    const cellId = `cell-${newRowIndex}-${newColIndex}`;
    document.getElementById(cellId)?.focus();
  };
  
  return (
    <>
      {/*Screen reader announcements*/}
      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {announcement}
      </div>

      <table role="table" aria-label={caption}>
        <caption className="table-caption">{caption}</caption>
        <thead>
          <tr role="row">
            {columns.map((column, index) => (
              <th
                key={column.id}
                role="columnheader"
                aria-sort={
                  sortState.column === column.id
                    ? sortState.direction === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : 'none'
                }
              >
                {column.sortable ? (
                  <button
                    className="sort-button"
                    onClick={() => handleSort(column.id)}
                    aria-label={`Sort by ${column.label} ${
                      sortState.column === column.id && sortState.direction === 'asc'
                        ? 'descending'
                        : 'ascending'
                    }`}
                  >
                    {column.label}
                    <SortIcon 
                      direction={sortState.column === column.id ? sortState.direction : null} 
                      aria-hidden="true"
                    />
                  </button>
                ) : (
                  column.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, rowIndex) => (
            <tr key={row.id} role="row">
              {columns.map((column, colIndex) => (
                <td
                  key={column.id}
                  role="cell"
                  id={`cell-${rowIndex}-${colIndex}`}
                  tabIndex={rowIndex === 0 && colIndex === 0 ? 0 : -1}
                  onKeyDown={(e) => handleKeyDown(e, rowIndex, colIndex)}
                >
                  {column.render ? column.render(row[column.id], row) : row[column.id]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      
      {data.length === 0 && (
        <div role="status" className="empty-state">
          No data available
        </div>
      )}
    </>
  );
}

// Accessible filter component
const TableFilters: React.FC<{
  filters: FilterConfig[];
  onFilterChange: (filters: FilterState) => void;
}> = ({ filters, onFilterChange }) => {
  const [filterState, setFilterState] = useState<FilterState>({});
  const [announcement, setAnnouncement] = useState('');
  
  const handleFilterChange = (filterId: string, value: any) => {
    const newState = { ...filterState, [filterId]: value };
    setFilterState(newState);
    onFilterChange(newState);

    // Announce filter changes
    const activeFilters = Object.entries(newState)
      .filter(([_, value]) => value)
      .map(([key, value]) => `${key}: ${value}`)
      .join(', ');
    
    setAnnouncement(
      activeFilters 
        ? `Filters applied: ${activeFilters}` 
        : 'All filters cleared'
    );
  };
  
  return (
    <div role="group" aria-label="Table filters">
      <div role="status" aria-live="polite" className="sr-only">
        {announcement}
      </div>

      {filters.map(filter => (
        <div key={filter.id} className="filter-group">
          <label htmlFor={`filter-${filter.id}`}>
            {filter.label}
            {filter.required && (
              <span aria-label="required" className="required">*</span>
            )}
          </label>
          
          {filter.type === 'select' ? (
            <select
              id={`filter-${filter.id}`}
              value={filterState[filter.id] || ''}
              onChange={(e) => handleFilterChange(filter.id, e.target.value)}
              aria-describedby={`filter-help-${filter.id}`}
            >
              <option value="">All</option>
              {filter.options?.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={`filter-${filter.id}`}
              type={filter.type}
              value={filterState[filter.id] || ''}
              onChange={(e) => handleFilterChange(filter.id, e.target.value)}
              aria-describedby={`filter-help-${filter.id}`}
            />
          )}
          
          {filter.helpText && (
            <span id={`filter-help-${filter.id}`} className="help-text">
              {filter.helpText}
            </span>
          )}
        </div>
      ))}
      
      <button
        onClick={() => {
          setFilterState({});
          onFilterChange({});
        }}
        className="clear-filters"
      >
        Clear all filters
      </button>
    </div>
  );
};

```
</recommended>
</example>
</examples>

## Domain-Driven Architecture

### Folder Organization by Domain

<domain_structure>
Organize code by business domains to maintain high cohesion within features and low coupling between them. Each domain should be self-contained with clear boundaries and explicit public APIs.
</domain_structure>

<folder_architecture>
```

src/
├── shared/                    # Truly shared, generic utilities
│   ├── components/           # Generic UI components (Button, Modal, etc.)
│   │   ├── Button/
│   │   │   ├── Button.tsx
│   │   │   ├── Button.test.tsx
│   │   │   ├── Button.stories.tsx
│   │   │   └── index.ts
│   │   └── Modal/
│   ├── hooks/               # Generic hooks (useDebounce, useLocalStorage)
│   ├── utils/               # Generic utilities (formatters, validators)
│   └── types/               # Shared TypeScript types
│
├── lib/                     # External library configurations
│   ├── api/                # API client setup
│   ├── analytics/          # Analytics configuration
│   └── monitoring/         # Error monitoring setup
│
├── domains/                 # Business domains
│   ├── auth/
│   │   ├── components/     # Auth-specific components
│   │   ├── hooks/         # Auth-specific hooks
│   │   ├── services/      # Auth API calls and business logic
│   │   ├── stores/        # Auth state management
│   │   ├── types/         # Auth types and interfaces
│   │   ├── utils/         # Auth utilities
│   │   ├── __tests__/     # Auth tests
│   │   └── index.ts       # Public API exports
│   │
│   ├── products/
│   │   ├── components/
│   │   │   ├── ProductList/
│   │   │   ├── ProductDetail/
│   │   │   └── ProductFilters/
│   │   ├── hooks/
│   │   │   ├── useProducts.ts
│   │   │   ├── useProductFilters.ts
│   │   │   └── useProductSearch.ts
│   │   ├── services/
│   │   │   ├── productApi.ts
│   │   │   └── productTransformers.ts
│   │   └── [similar structure]
│   │
│   └── checkout/
│       └── [similar structure]
│
├── pages/                   # Route-level components
│   ├── HomePage/
│   ├── ProductsPage/
│   └── CheckoutPage/
│
└── app/                     # App-level configuration
    ├── App.tsx
    ├── AppProviders.tsx
    ├── AppRoutes.tsx
    └── index.tsx

```
</folder_architecture>

<examples>
<example>
<situation>Implementing a complete domain module</situation>
<recommended>
```typescript
// domains/products/index.ts - Public API
export { ProductList } from './components/ProductList';
export { ProductDetail } from './components/ProductDetail';
export { useProducts, useProduct } from './hooks';
export type { Product, ProductFilter } from './types';

// domains/products/types/index.ts
export interface Product {
  id: string;
  name: string;
  description: string;
  price: Money;
  images: ProductImage[];
  category: Category;
  tags: string[];
  availability: ProductAvailability;
}

export interface ProductFilter {
  categories?: string[];
  priceRange?: PriceRange;
  tags?: string[];
  availability?: AvailabilityStatus[];
  searchTerm?: string;
}

// domains/products/hooks/useProducts.ts
export function useProducts(filters?: ProductFilter) {
  return useQuery({
    queryKey: ['products', filters],
    queryFn: () => productService.fetchProducts(filters),
    staleTime: 5 * 60 * 1000,
    select: (data) => transformProductsForDisplay(data),
  });
}

// domains/products/services/productApi.ts
class ProductService {
  async fetchProducts(filters?: ProductFilter): Promise<Product[]> {
    const params = buildQueryParams(filters);
    const response = await apiClient.get<ApiProductResponse>('/products', { params });
    return response.data.products.map(transformApiProduct);
  }
  
  async fetchProduct(id: string): Promise<Product> {
    const response = await apiClient.get<ApiProductResponse>(`/products/${id}`);
    return transformApiProduct(response.data);
  }
}

export const productService = new ProductService();

// domains/products/components/ProductList/ProductList.tsx
export const ProductList: React.FC<ProductListProps> = ({ 
  filters,
  onProductSelect,
  viewMode = 'grid' 
}) => {
  const { data: products, isLoading, error } = useProducts(filters);
  const { trackEvent } = useAnalytics();
  
  const handleProductClick = (product: Product) => {
    trackEvent('product_clicked', {
      productId: product.id,
      productName: product.name,
      category: product.category.name,
    });
    onProductSelect?.(product);
  };
  
  if (isLoading) return <ProductListSkeleton count={12} />;
  if (error) return <ProductListError error={error} onRetry={() => refetch()} />;
  if (!products?.length) return <EmptyProductList filters={filters} />;
  
  return (
    <div className={`product-list product-list--${viewMode}`}>
      {products.map(product => (
        <ProductCard
          key={product.id}
          product={product}
          onClick={() => handleProductClick(product)}
          viewMode={viewMode}
        />
      ))}
    </div>
  );
};
```

</recommended>
</example>
</examples>

## Modern React Patterns

### Concurrent Features and Suspense

<guideline>
Leverage React 18+ concurrent features to improve perceived performance and user experience. Use Suspense for data fetching, lazy loading, and coordinating loading states.
</guideline>

<examples>
<example>
<situation>Building a dashboard with multiple data dependencies</situation>
<recommended>
```tsx
// Configure suspense-enabled query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      suspense: true,
      useErrorBoundary: true,
      retry: (failureCount, error) => {
        if (error.status === 404) return false;
        return failureCount < 3;
      },
    },
  },
});

// Granular suspense boundaries for progressive loading
const DashboardPage: React.FC = () => {
  return (
    <DashboardLayout>
      <ErrorBoundary fallback={<HeaderError />}>
        <Suspense fallback={<HeaderSkeleton />}>
          <DashboardHeader />
        </Suspense>
      </ErrorBoundary>

      <div className="dashboard-grid">
        <ErrorBoundary fallback={<StatsError />}>
          <Suspense fallback={<StatsSkeleton />}>
            <StatsOverview />
          </Suspense>
        </ErrorBoundary>
        
        <ErrorBoundary fallback={<ChartError />}>
          <Suspense fallback={<ChartSkeleton />}>
            <RevenueChart />
          </Suspense>
        </ErrorBoundary>
        
        <ErrorBoundary fallback={<ActivityError />}>
          <Suspense fallback={<ActivitySkeleton />}>
            <RecentActivity />
          </Suspense>
        </ErrorBoundary>
      </div>
    </DashboardLayout>
  );
};

// Components that suspend
const StatsOverview: React.FC = () => {
  // These queries suspend until data is available
  const { data: userStats } = useUserStats();
  const { data: systemStats } = useSystemStats();
  
  return (
    <StatsGrid>
      <StatCard
        title="Active Users"
        value={userStats.activeUsers}
        change={userStats.userChange}
        trend={userStats.userTrend}
      />
      <StatCard
        title="Revenue"
        value={systemStats.revenue}
        change={systemStats.revenueChange}
        trend={systemStats.revenueTrend}
      />
    </StatsGrid>
  );
};

// Streaming SSR with suspense (Next.js app router)
export default async function ProductPage({ params }: { params: { id: string } }) {
  // This runs on the server
  const product = await getProduct(params.id);
  
  return (
    <div className="product-page">
      {/*This part renders immediately*/}
      <ProductHeader product={product} />

      {/* These parts can stream in later */}
      <Suspense fallback={<ReviewsSkeleton />}>
        <ProductReviews productId={params.id} />
      </Suspense>
      
      <Suspense fallback={<RecommendationsSkeleton />}>
        <ProductRecommendations productId={params.id} />
      </Suspense>
    </div>
  );
}

// Optimistic updates with transitions
const TodoList: React.FC = () => {
  const [todos, setTodos] = useState<Todo[]>([]);
  const [isPending, startTransition] = useTransition();
  
  const addTodo = (text: string) => {
    const newTodo = { id: nanoid(), text, completed: false };

    // Immediate update
    setTodos(prev => [...prev, newTodo]);
    
    // Deferred sync with server
    startTransition(async () => {
      try {
        await saveTodo(newTodo);
      } catch (error) {
        // Revert on failure
        setTodos(prev => prev.filter(t => t.id !== newTodo.id));
        toast.error('Failed to save todo');
      }
    });
  };
  
  return (
    <div className={isPending ? 'saving' : ''}>
      <TodoInput onAdd={addTodo} disabled={isPending} />
      <TodoItems todos={todos} />
    </div>
  );
};

```
</recommended>
</example>
</examples>

### Server Components (Next.js 13+)

<guideline>
When using Next.js App Router, maximize the benefits of React Server Components. Keep components on the server by default, moving to client components only when necessary for interactivity.
</guideline>

<examples>
<example>
<situation>Building a product catalog with server and client components</situation>
<recommended>
```tsx
// app/products/page.tsx - Server Component (default)
import { Suspense } from 'react';
import { getCategories, getFeaturedProducts } from '@/lib/api';

export default async function ProductsPage({
  searchParams,
}: {
  searchParams: { category?: string; sort?: string; page?: string };
}) {
  // Parallel data fetching on server
  const [categories, featuredProducts] = await Promise.all([
    getCategories(),
    getFeaturedProducts(),
  ]);
  
  return (
    <div className="products-page">
      {/* Static content - no JS needed */}
      <PageHeader 
        title="Our Products" 
        description="Discover our collection"
      />
      
      {/* Client component for interactivity */}
      <ProductFilters 
        categories={categories}
        initialFilters={searchParams}
      />
      
      {/* Server component with streaming */}
      <Suspense 
        key={JSON.stringify(searchParams)} 
        fallback={<ProductGridSkeleton />}
      >
        <ProductGrid filters={searchParams} />
      </Suspense>
      
      {/* Static featured section */}
      <FeaturedProducts products={featuredProducts} />
    </div>
  );
}

// app/products/ProductGrid.tsx - Server Component
async function ProductGrid({ filters }: { filters: ProductFilters }) {
  // Direct database query or API call
  const products = await getProducts(filters);
  
  return (
    <div className="product-grid">
      {products.map(product => (
        <ProductCard key={product.id} product={product} />
      ))}
      
      {products.length === 0 && (
        <EmptyState 
          title="No products found"
          description="Try adjusting your filters"
        />
      )}
    </div>
  );
}

// app/products/ProductCard.tsx - Server Component
function ProductCard({ product }: { product: Product }) {
  return (
    <article className="product-card">
      <img 
        src={product.image} 
        alt={product.name}
        loading="lazy"
      />
      <h3>{product.name}</h3>
      <p className="price">{formatPrice(product.price)}</p>
      
      {/* Client component only for the interactive part */}
      <AddToCartButton productId={product.id} />
    </article>
  );
}

// app/products/ProductFilters.tsx - Client Component
'use client';

import { useRouter, usePathname } from 'next/navigation';
import { useTransition } from 'react';

export function ProductFilters({ 
  categories, 
  initialFilters 
}: ProductFiltersProps) {
  const router = useRouter();
  const pathname = usePathname();
  const [isPending, startTransition] = useTransition();
  
  const updateFilters = (newFilters: Partial<ProductFilters>) => {
    const params = new URLSearchParams(window.location.search);
    
    Object.entries(newFilters).forEach(([key, value]) => {
      if (value) {
        params.set(key, value);
      } else {
        params.delete(key);
      }
    });
    
    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`);
    });
  };
  
  return (
    <div className={`filters ${isPending ? 'updating' : ''}`}>
      <CategoryFilter
        categories={categories}
        selected={initialFilters.category}
        onChange={(category) => updateFilters({ category })}
      />
      
      <SortDropdown
        value={initialFilters.sort}
        onChange={(sort) => updateFilters({ sort })}
      />
      
      <PriceRangeFilter
        onChange={(priceRange) => updateFilters({ priceRange })}
      />
    </div>
  );
}

// app/products/AddToCartButton.tsx - Client Component
'use client';

import { useCartStore } from '@/stores/cart';
import { useTransition } from 'react';

export function AddToCartButton({ productId }: { productId: string }) {
  const addToCart = useCartStore(state => state.addItem);
  const [isPending, startTransition] = useTransition();
  
  const handleAdd = () => {
    startTransition(async () => {
      await addToCart(productId);
    });
  };
  
  return (
    <button 
      onClick={handleAdd}
      disabled={isPending}
      className="add-to-cart-btn"
    >
      {isPending ? 'Adding...' : 'Add to Cart'}
    </button>
  );
}
```

</recommended>
</example>
</examples>

## Conclusion

<summary>
These guidelines represent current best practices for building modern React applications. They emphasize clarity, maintainability, performance, and accessibility as core requirements, not optional features.
</summary>

<key_principles>
1. **Code for humans first** - Optimize for readability and maintainability
2. **Test user journeys** - Focus on behavior over implementation
3. **Build inclusively** - Accessibility is a fundamental requirement
4. **Measure before optimizing** - Use data to guide performance improvements
5. **Handle errors gracefully** - Every error should have a recovery path
6. **Stay current** - Adopt new patterns that provide clear benefits
</key_principles>

<continuous_improvement>
Review and update these guidelines quarterly to incorporate:
- New React features and patterns
- Team learnings and discoveries
- Performance insights from production
- Accessibility improvements
- Security best practices
</continuous_improvement>

<thinking>
Remember: The best code is code that your team can understand, modify, and maintain efficiently. These guidelines should enable that goal while building applications that delight users.
</thinking>

<important_reminders>
- ALWAYS use TypeScript for type safety
- NEVER compromise on accessibility
- ALWAYS measure performance impact before optimizing
- NEVER skip testing for critical user paths
- ALWAYS consider mobile users first
</important_reminders>
