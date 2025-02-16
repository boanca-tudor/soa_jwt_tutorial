# soa_jwt_tutorial

# Securing a REST API with Spring Boot, Spring Security, and JWTs

## Introduction
Security is a crucial aspect of any web application, especially when dealing with REST APIs. In this tutorial, we will walk through securing a Spring Boot REST API using **Spring Security** and **JSON Web Tokens (JWTs)**. JWTs allow stateless authentication, making them ideal for modern microservices-based architectures.

---

## 1. Setting Up the Project
To create a Spring Boot project that utilizes JWTs, you can generate a basic working template using **Spring Initializr** with the following dependencies:

- **Spring Web**
- **Spring Security**
- **Spring Data JPA**
- **Lombok** (to simplify code)
- **Database Driver** of your choice

### **Adding JWT Dependencies**
After creating the project, add the JWT dependencies in your `build.gradle.kts` file:

```kotlin
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
}
```

---

## 2. Creating a User Entity and Repository
### **User Entity**
```java
@Entity
@Table(name = "users")
@Getter
@Setter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String role;
}
```

### **User Repository**
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

---

## 3. Implementing JWT Authentication
### **3.1 Creating a JWT Utility Class**

```java
@Component
public class JwtUtil {
   // must be a base64 string, at least 32 bytes since we are using HMAC SHA-256
   private final String SECRET_KEY = "jrwBtd+VE5GbcHcosHObJTNYNeRoXWcXaBNAXuccfkk=";

   private SecretKey getSigningKey() {
      byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
      return Keys.hmacShaKeyFor(keyBytes);
   }

   public String generateToken(String username) {
      return Jwts.builder()
              .subject(username)
              .issuedAt(new Date())
              .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
              .signWith(getSigningKey())
              .compact();
   }

   public String extractUsername(String token) {
      JwtParser parser = Jwts.parser()
              .verifyWith(getSigningKey())
              .build();

      return parser.parseSignedClaims(token).getPayload().getSubject();
   }
}
```

### **3.2 Creating a JWT Filter**

```java
@Component
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            String username = jwtUtil.extractUsername(token);
            
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        chain.doFilter(request, response);
    }
}
```

---

## 4. Configuring Spring Security

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
      return httpSecurity
              .csrf(AbstractHttpConfigurer::disable)
              .authorizeHttpRequests(registry -> {
                 registry.requestMatchers("/login").permitAll()
                         .requestMatchers("/register").permitAll()
                         .anyRequest().authenticated();
              })
              .sessionManagement(session ->
                      session.sessionCreationPolicy(STATELESS))
              .addFilterBefore(
                      jwtFilter(),
                      UsernamePasswordAuthenticationFilter.class
              )
              .build();
   }

   @Bean
   protected JwtFilter jwtFilter() {
      return new JwtFilter();
   }
}
```

---

## 5. Implementing User Authentication

```java
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        String token = jwtUtil.generateToken(request.getUsername());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}

@Getter
@Setter
class AuthRequest {
    private String username;
    private String password;
}

@Getter
@Setter
class AuthResponse {
    private String token;
    public AuthResponse(String token) { this.token = token; }
}
```

---

## 6. Testing the API

### **Steps to Test**
1. **Register a user** (via database or a dedicated endpoint).
2. **Obtain a JWT** by sending a `POST` request to `/auth/login` with valid credentials.
3. **Use the JWT** in the `Authorization` header to access protected endpoints:
   ```
   Authorization: Bearer your-jwt-token
   ```

---

## Conclusion
In this tutorial, we covered:
- Setting up Spring Security with JWT authentication.
- Creating an authentication mechanism.
- Configuring Spring Boot to validate JWTs for secure API access.

This setup ensures **secure and stateless** authentication for your REST API. 🚀

