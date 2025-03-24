# cp-abe
Thought for 3 seconds### CP-ABE Secure File Sharing System

## Table of Contents

1. [Project Overview](#project-overview)
2. [User Authentication and Login Workflow](#user-authentication-and-login-workflow)
3. [CP-ABE Implementation Workflow](#cp-abe-implementation-workflow)
4. [Database Interaction and Workflow](#database-interaction-and-workflow)
5. [File Upload and Sharing Workflow](#file-upload-and-sharing-workflow)
6. [Security Considerations and Measures](#security-considerations-and-measures)
7. [Adapting the Workflow to Other Projects](#adapting-the-workflow-to-other-projects)
8. [Complete Application Workflow](#complete-application-workflow)
9. [Installation and Setup](#installation-and-setup)
10. [Troubleshooting](#troubleshooting)


## Project Overview

The CP-ABE Secure File Sharing System is a web application that implements Ciphertext-Policy Attribute-Based Encryption (CP-ABE) for secure file sharing. The system allows users to upload files, which are encrypted based on user-defined access policies, and then shared with other users. Only users who have the required attributes (defined in the policy) will be able to decrypt and access the file.

Key features include:

- User registration with attribute assignment (department, role, clearance level)
- Secure file upload with policy definition
- Fine-grained access control based on user attributes
- Secure file download with attribute-based decryption
- Visual policy builder for creating access policies


## User Authentication and Login Workflow

### Registration Process

1. **User Data Collection**:

1. The registration form (`app/register/page.tsx`) collects the following information:

1. Full Name
2. Email
3. Password
4. Department (selected from predefined options)
5. Role (selected from predefined options)
6. Clearance Level (selected from predefined options)






2. **Client-Side Validation**:

1. The form validates that all required fields are filled
2. Passwords must match (password and confirm password fields)
3. Email format is validated



3. **Server-Side Processing**:

1. When the form is submitted, the data is sent to the `/api/auth/register` endpoint
2. The server validates the data again to ensure all required fields are present
3. The server checks if the email is already registered



4. **Password Security**:

1. Passwords are hashed using SHA-256 (in a production environment, bcrypt or Argon2 would be used)
2. The hashing process in `app/api/auth/register/route.ts`:


```typescript
const hashedPassword = createHash('sha256').update(password).digest('hex');
```


5. **User Attribute Storage**:

1. User attributes are stored as a nested object within the user record
2. The structure in the database:


```javascript
{
  id: "user_id",
  name: "User Name",
  email: "user@example.com",
  password: "hashed_password",
  attributes: {
    department: "IT",
    role: "Admin",
    clearanceLevel: "Level3"
  },
  createdAt: "timestamp"
}
```


6. **User Record Creation**:

1. A unique user ID is generated using `crypto.randomUUID()`
2. The complete user record is stored in the database
3. A success response is sent back to the client





### Login Process

1. **Credential Collection**:

1. The login form (`app/login/page.tsx`) collects:

1. Email
2. Password






2. **Server-Side Validation**:

1. When the form is submitted, credentials are sent to the `/api/auth/login` endpoint
2. The server validates that both email and password are provided
3. The password is hashed using the same algorithm as during registration
4. The server queries the database to find a user with matching email and hashed password



3. **Session Management**:

1. Upon successful authentication, a session token is generated using `crypto.randomUUID()`
2. The token is set as an HTTP-only cookie:


```typescript
cookies().set({
  name: 'session_token',
  value: sessionToken,
  httpOnly: true,
  path: '/',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 60 * 60 * 24 * 7, // 1 week
});
```

1. The session token is associated with the user ID in a sessions store



4. **User Information Retrieval**:

1. After login, the client calls the `/api/auth/user` endpoint to get the user's information
2. The server extracts the session token from the cookies
3. The server looks up the user ID associated with the session token
4. The user's information, including attributes, is retrieved from the database and sent to the client
5. The user's password is excluded from the response



5. **Attribute Usage in Application**:

1. The user's attributes are stored in the client-side state
2. These attributes are used to:

1. Display the user's profile information
2. Determine which files the user can access
3. Check if the user can decrypt files based on access policies








## CP-ABE Implementation Workflow

### CP-ABE File Upload Process

1. **Policy Definition**:

1. When uploading a file, the user defines an access policy using the `PolicyBuilder` component
2. The policy is a boolean expression over attributes, such as:

```plaintext
department == "HR" AND clearanceLevel >= "Level2"
```


3. The policy builder provides a visual interface for creating these expressions



2. **File Encryption Process**:

1. When a file is uploaded, the following steps occur in `lib/cp-abe.ts`:


a. **File Reading**:

1. The file is read as a Buffer


```typescript
const fileBuffer = Buffer.from(await file.arrayBuffer());
```

b. **Symmetric Key Generation**:

1. A random 256-bit symmetric key is generated for encrypting the file


```typescript
const symmetricKey = randomBytes(32);
```

c. **Initialization Vector Generation**:

1. A random 16-byte initialization vector (IV) is generated


```typescript
const iv = randomBytes(16);
```

d. **File Encryption**:

1. The file is encrypted using AES-256-GCM with the symmetric key


```typescript
const cipher = createCipheriv('aes-256-gcm', symmetricKey, iv);
const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
```

e. **Policy-Based Key Encryption**:

1. A policy key is derived from the access policy and a master key


```typescript
const policyKey = generateKey(policy, masterKey);
```

1. The symmetric key is encrypted with the policy key


```typescript
const keyCipher = createCipheriv('aes-256-cbc', policyKey, iv);
const encryptedKey = Buffer.concat([keyCipher.update(symmetricKey), keyCipher.final()]);
```

f. **Result Packaging**:

1. The encrypted file, encrypted key, IV, and policy are packaged together


```typescript
return {
  ciphertext: encryptedData,
  encryptedKey,
  iv,
  policy
};
```


3. **Database Storage**:

1. The encrypted file and metadata are stored in the database:

1. File ID (generated using `crypto.randomUUID()`)
2. File name
3. Description
4. Access policy
5. User ID of uploader
6. Upload timestamp
7. File size
8. Encryption result (ciphertext, encrypted key, IV)








### CP-ABE Decryption Logic

1. **Access Request**:

1. When a user attempts to download a file, a request is sent to `/api/files/download/[fileId]`
2. The request includes the file ID and the user ID



2. **Attribute Retrieval**:

1. The server retrieves the user's attributes from the database
2. These attributes will be used to check against the file's access policy



3. **Policy Evaluation**:

1. The server evaluates if the user's attributes satisfy the file's access policy
2. This is done in the `evaluatePolicy` function in `lib/cp-abe.ts`:


```typescript
function evaluatePolicy(policy: string, attributes: UserAttributes): boolean {
  // Split the policy into conditions
  const conditions = policy.split(" AND ");
  
  // Check if all conditions are satisfied
  return conditions.every(condition => {
    // Parse and evaluate each condition
    // ...
  });
}
```


4. **Decryption Process**:

1. If the user's attributes satisfy the policy, the decryption process begins:


a. **Policy Key Derivation**:

1. The same policy key is derived as during encryption


```typescript
const policyKey = generateKey(encryptionResult.policy, masterKey);
```

b. **Symmetric Key Decryption**:

1. The encrypted symmetric key is decrypted using the policy key


```typescript
const keyDecipher = createDecipheriv('aes-256-cbc', policyKey, encryptionResult.iv);
const symmetricKey = Buffer.concat([
  keyDecipher.update(encryptionResult.encryptedKey),
  keyDecipher.final()
]);
```

c. **File Decryption**:

1. The encrypted file is decrypted using the symmetric key


```typescript
const decipher = createDecipheriv('aes-256-gcm', symmetricKey, encryptionResult.iv);
return Buffer.concat([
  decipher.update(encryptionResult.ciphertext),
  decipher.final()
]);
```


5. **File Delivery**:

1. If decryption is successful, the decrypted file is sent to the user
2. If the user's attributes do not satisfy the policy, an access denied error is returned





## Database Interaction and Workflow

### User Database Management

1. **Users Table Structure**:

```javascript
{
  id: String,           // Primary key, UUID
  name: String,         // User's full name
  email: String,        // User's email (unique)
  password: String,     // Hashed password
  attributes: {         // Nested object of user attributes
    department: String, // Department (e.g., "IT", "HR")
    role: String,       // Role (e.g., "Admin", "Manager")
    clearanceLevel: String // Clearance level (e.g., "Level1", "Level2")
  },
  createdAt: String     // Timestamp of account creation
}
```


2. **User Attribute Storage**:

1. Attributes are stored as a nested object within the user record
2. This allows for flexible attribute addition without schema changes
3. Attributes are strongly typed in TypeScript for type safety



3. **User Queries**:

1. Users are queried by email for login:


```typescript
const user = Object.values(users).find(
  (u: any) => u.email === email && u.password === hashedPassword
);
```

1. Users are queried by ID for profile information:


```typescript
const user = users[userId];
```




### File Metadata and Access Policy Storage

1. **Files Table Structure**:

```javascript
{
  id: String,           // Primary key, UUID
  fileName: String,     // Name of the file
  description: String,  // Optional description
  policy: String,       // Access policy as a string
  uploadedBy: String,   // Foreign key to Users table
  uploadedAt: String,   // Timestamp of upload
  fileSize: Number,     // Size of the file in bytes
  encryptionResult: {   // Encryption details
    ciphertext: Buffer, // Encrypted file content
    encryptedKey: Buffer, // Encrypted symmetric key
    iv: Buffer,         // Initialization vector
    policy: String      // Copy of the access policy
  }
}
```


2. **Access Policy Storage**:

1. Policies are stored as strings in the format:

```plaintext
department == "HR" AND clearanceLevel >= "Level2"
```


2. This format allows for easy parsing and evaluation
3. The policy is stored both in the file record and in the encryption result



3. **File Queries**:

1. Files are queried by ID for download:


```typescript
const file = fileStorage[fileId];
```

1. Files are queried by uploader for "My Files":


```typescript
const userFiles = Object.values(files).filter(file => file.uploadedBy === userId);
```

1. Files are queried for "Shared With Me" by excluding the user's uploads:


```typescript
const sharedFiles = Object.values(files).filter(file => file.uploadedBy !== userId);
```




### Encryption Key Storage

1. **Encryption Keys Management**:

1. In the current implementation, encryption keys are derived from:

1. The access policy
2. A master key (which would be securely stored in a production environment)



2. The derived keys are not stored directly; instead, the policy and master key are used to regenerate them when needed



2. **Key Security**:

1. The symmetric key used for file encryption is encrypted with a policy-based key
2. The encrypted symmetric key is stored with the file
3. Only users whose attributes satisfy the policy can derive the correct key to decrypt the symmetric key



3. **Key-User-File Relationship**:

1. Each file has its own symmetric key
2. The symmetric key is encrypted based on the access policy
3. Users with attributes satisfying the policy can derive the key needed to decrypt the symmetric key
4. This creates an implicit relationship between users, files, and keys without storing explicit mappings





## File Upload and Sharing Workflow

### File Upload Process

1. **Frontend Collection**:

1. The `FileUpload` component (`components/file-upload.tsx`) collects:

1. The file via a file input
2. A file name (defaulting to the original file name)
3. An optional description
4. An access policy via the `PolicyBuilder` component






2. **Policy Definition**:

1. The `PolicyBuilder` component (`components/policy-builder.tsx`) allows users to:

1. Create conditions using a visual builder
2. Combine conditions with AND operators
3. Manually enter a policy expression



2. The resulting policy is a string like:

```plaintext
department == "HR" AND clearanceLevel >= "Level2"
```





3. **Form Submission**:

1. When the form is submitted, the following checks are performed:

1. File is selected
2. File name is provided
3. Access policy is defined



2. If all checks pass, the upload process begins



4. **Backend Processing**:

1. The file and metadata are sent to the `/api/files/upload` endpoint
2. The server validates the input
3. The file is read as a Buffer
4. The file is encrypted using CP-ABE with the provided policy
5. A file record is created with:

1. Generated file ID
2. File name
3. Description
4. Access policy
5. User ID of uploader
6. Current timestamp
7. File size
8. Encryption result






5. **Response Handling**:

1. On successful upload, the server returns a success response with the file ID
2. The client displays a success message
3. The form is reset for another upload
4. On failure, an error message is displayed





### File Sharing and Access Control

1. **File Discovery**:

1. Users can browse files in two tabs:

1. "My Files": Files uploaded by the user
2. "Shared With Me": Files uploaded by other users






2. **Access Determination**:

1. For each file, the system determines if the user can access it:

1. The user's attributes are retrieved
2. The file's access policy is evaluated against these attributes
3. A `canAccess` flag is added to each file in the response






3. **File Display**:

1. Files are displayed with:

1. File name
2. Description (if available)
3. File size
4. Upload date
5. Access policy
6. Download button (enabled only if `canAccess` is true)






4. **Download Process**:

1. When a user clicks "Download":

1. A request is sent to `/api/files/download/[fileId]` with the user ID
2. The server retrieves the file and the user's attributes
3. The server checks if the attributes satisfy the policy
4. If access is granted, the file is decrypted and sent to the user
5. If access is denied, an error message is displayed






5. **Access Denial Handling**:

1. Files that the user cannot access are still visible but:

1. The download button is disabled
2. The button text changes to "Access Denied"



2. This allows users to see what files exist but enforces the access control policy





## Security Considerations and Measures

### Password Security

1. **Password Hashing**:

1. Passwords are hashed using SHA-256 (in a production environment, bcrypt or Argon2 would be used)
2. The hashing process:


```typescript
const hashedPassword = createHash('sha256').update(password).digest('hex');
```


2. **Password Storage**:

1. Only the hashed password is stored in the database
2. The original password is never stored
3. Password comparison is done by hashing the input password and comparing with the stored hash



3. **Password Validation**:

1. Passwords must be confirmed during registration
2. In a production environment, password strength requirements would be enforced





### HTTPS and Secure Communication

1. **Secure Cookies**:

1. Session cookies are set with the `secure` flag in production:


```typescript
cookies().set({
  // ...
  secure: process.env.NODE_ENV === 'production',
  // ...
});
```


2. **HTTP-Only Cookies**:

1. Cookies are set with the `httpOnly` flag to prevent JavaScript access:


```typescript
cookies().set({
  // ...
  httpOnly: true,
  // ...
});
```


3. **API Security**:

1. All API endpoints validate the session token before processing requests
2. User IDs are verified to prevent unauthorized access to other users' data



4. **CORS Configuration**:

1. In a production environment, CORS would be configured to restrict API access to trusted domains





### Encryption Key Management

1. **Master Key Security**:

1. The master key is a constant in the current implementation
2. In a production environment, it would be:

1. Stored in a secure key management service
2. Rotated periodically
3. Never exposed in the application code






2. **Symmetric Key Protection**:

1. Each file has its own symmetric key
2. The symmetric key is encrypted with a policy-based key
3. The symmetric key is never stored in plaintext



3. **Key Derivation**:

1. Keys are derived using cryptographic hash functions
2. The derivation process combines:

1. The access policy
2. The master key





```typescript
function generateKey(policy: string, masterKey: Buffer): Buffer {
  const hash = createHash('sha256');
  hash.update(policy);
  hash.update(masterKey);
  return hash.digest();
}
```


4. **Secure Key Distribution**:

1. Keys are not directly distributed to users
2. Instead, users with the right attributes can derive the keys when needed
3. This approach eliminates the need to store and manage keys for each user





## Adapting the Workflow to Other Projects

### Adapting User Authentication

1. **Core Components**:

1. User registration form with attribute collection
2. Login form with credential validation
3. Session management using secure cookies
4. User profile with attribute display



2. **Implementation Steps**:

1. Create a user model with attributes:


```typescript
interface User {
  id: string;
  name: string;
  email: string;
  password: string; // Hashed
  attributes: {
    [key: string]: string;
  };
  createdAt: string;
}
```

1. Implement registration endpoint:


```typescript
// POST /api/auth/register
export async function POST(request: NextRequest) {
  const { name, email, password, attributes } = await request.json();
  // Validate input
  // Check if email exists
  // Hash password
  // Create user
  // Return success
}
```

1. Implement login endpoint:


```typescript
// POST /api/auth/login
export async function POST(request: NextRequest) {
  const { email, password } = await request.json();
  // Validate input
  // Hash password
  // Find user
  // Create session
  // Set cookie
  // Return success
}
```

1. Implement user info endpoint:


```typescript
// GET /api/auth/user
export async function GET(request: NextRequest) {
  // Get session token from cookies
  // Find user ID from session
  // Get user info
  // Return user info (excluding password)
}
```


3. **Database Considerations**:

1. Use a proper database like MySQL, PostgreSQL, or MongoDB
2. Create indexes on email for fast lookups
3. Use foreign keys to link users to other entities
4. Store sessions in a separate table with expiration times





### Implementing CP-ABE

1. **Core Components**:

1. Policy definition interface
2. Encryption function
3. Decryption function
4. Policy evaluation function



2. **Implementation Steps**:

1. Define the CP-ABE interfaces:


```typescript
interface UserAttributes {
  [key: string]: string;
}

interface EncryptionResult {
  ciphertext: Buffer;
  encryptedKey: Buffer;
  iv: Buffer;
  policy: string;
}
```

1. Implement the encryption function:


```typescript
async function encrypt(
  data: Buffer,
  policy: string,
  masterKey: Buffer
): Promise<EncryptionResult> {
  // Generate symmetric key
  // Generate IV
  // Encrypt data with symmetric key
  // Derive policy key
  // Encrypt symmetric key with policy key
  // Return result
}
```

1. Implement the decryption function:


```typescript
async function decrypt(
  encryptionResult: EncryptionResult,
  userAttributes: UserAttributes,
  masterKey: Buffer
): Promise<Buffer | null> {
  // Check if attributes satisfy policy
  // Derive policy key
  // Decrypt symmetric key
  // Decrypt data
  // Return decrypted data
}
```

1. Implement the policy evaluation function:


```typescript
function evaluatePolicy(
  policy: string,
  attributes: UserAttributes
): boolean {
  // Parse policy
  // Evaluate conditions
  // Return result
}
```


3. **Libraries and Tools**:

1. For a production implementation, consider:

1. [OpenABE](https://github.com/zeutro/openabe): An open-source ABE library
2. [Charm-Crypto](https://github.com/JHUISI/charm): A Python framework for cryptographic prototyping
3. [CPABE toolkit](https://acsc.cs.utexas.edu/cpabe/): A C implementation of CP-ABE






4. **Integration with File System**:

1. Implement file upload with policy definition
2. Store encrypted files in a secure location
3. Implement file download with policy checking
4. Handle access denied scenarios gracefully





### Database Structure for File Management

1. **Core Tables**:

1. Users: Store user information and attributes
2. Files: Store file metadata and encryption details
3. Sessions: Store user sessions (optional)



2. **Users Table Schema**:

```sql
CREATE TABLE users (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(64) NOT NULL,
  attributes JSON NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```


3. **Files Table Schema**:

```sql
CREATE TABLE files (
  id VARCHAR(36) PRIMARY KEY,
  file_name VARCHAR(255) NOT NULL,
  description TEXT,
  policy TEXT NOT NULL,
  uploaded_by VARCHAR(36) NOT NULL,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  file_size BIGINT NOT NULL,
  ciphertext LONGBLOB NOT NULL,
  encrypted_key BLOB NOT NULL,
  iv BLOB NOT NULL,
  FOREIGN KEY (uploaded_by) REFERENCES users(id)
);
```


4. **Optimization Techniques**:

1. Create indexes on frequently queried columns:


```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_files_uploaded_by ON files(uploaded_by);
```

1. Use foreign key constraints to maintain referential integrity:


```sql
ALTER TABLE files ADD CONSTRAINT fk_files_users
FOREIGN KEY (uploaded_by) REFERENCES users(id);
```

1. Consider partitioning large tables by upload date for better performance
2. Use prepared statements for all database queries to prevent SQL injection





## Complete Application Workflow

### End-to-End Workflow

1. **User Registration**:

1. User fills out registration form with personal details and attributes
2. Form is validated client-side
3. Data is sent to server
4. Server validates data
5. Password is hashed
6. User record is created in database
7. Success response is sent to client
8. User is redirected to login page



2. **User Login**:

1. User enters email and password
2. Data is sent to server
3. Server validates credentials
4. Session token is generated
5. Session cookie is set
6. Success response is sent to client
7. User is redirected to dashboard



3. **Dashboard Loading**:

1. Client requests user information
2. Server validates session token
3. User information is retrieved
4. User's files are retrieved
5. Shared files are retrieved
6. Data is sent to client
7. Dashboard is rendered with user information and files



4. **File Upload**:

1. User selects a file
2. User defines an access policy
3. Form is validated client-side
4. File and metadata are sent to server
5. Server validates input
6. File is encrypted using CP-ABE
7. File record is created in database
8. Success response is sent to client
9. Success message is displayed



5. **File Browsing**:

1. User navigates to "My Files" or "Shared With Me" tab
2. Client requests files from server
3. Server validates session token
4. Files are retrieved from database
5. For each file, server checks if user's attributes satisfy the policy
6. Files with access information are sent to client
7. Files are displayed with appropriate access indicators



6. **File Download**:

1. User clicks "Download" on a file
2. Client sends download request to server
3. Server validates session token
4. Server retrieves file and user attributes
5. Server checks if attributes satisfy policy
6. If access is granted:

1. File is decrypted
2. Decrypted file is sent to client
3. File is saved by the browser



7. If access is denied:

1. Error response is sent to client
2. Error message is displayed






7. **Logout**:

1. User clicks "Logout"
2. Client sends logout request to server
3. Server invalidates session
4. Session cookie is cleared
5. User is redirected to login page





### Workflow Diagram

```mermaid
CP-ABE File Sharing Workflow.download-icon {
            cursor: pointer;
            transform-origin: center;
        }
        .download-icon .arrow-part {
            transition: transform 0.35s cubic-bezier(0.35, 0.2, 0.14, 0.95);
             transform-origin: center;
        }
        button:has(.download-icon):hover .download-icon .arrow-part, button:has(.download-icon):focus-visible .download-icon .arrow-part {
          transform: translateY(-1.5px);
        }
        #mermaid-diagram-r24sm{font-family:var(--font-geist-sans);font-size:12px;fill:#000000;}#mermaid-diagram-r24sm .error-icon{fill:#552222;}#mermaid-diagram-r24sm .error-text{fill:#552222;stroke:#552222;}#mermaid-diagram-r24sm .edge-thickness-normal{stroke-width:1px;}#mermaid-diagram-r24sm .edge-thickness-thick{stroke-width:3.5px;}#mermaid-diagram-r24sm .edge-pattern-solid{stroke-dasharray:0;}#mermaid-diagram-r24sm .edge-thickness-invisible{stroke-width:0;fill:none;}#mermaid-diagram-r24sm .edge-pattern-dashed{stroke-dasharray:3;}#mermaid-diagram-r24sm .edge-pattern-dotted{stroke-dasharray:2;}#mermaid-diagram-r24sm .marker{fill:#666;stroke:#666;}#mermaid-diagram-r24sm .marker.cross{stroke:#666;}#mermaid-diagram-r24sm svg{font-family:var(--font-geist-sans);font-size:12px;}#mermaid-diagram-r24sm p{margin:0;}#mermaid-diagram-r24sm .label{font-family:var(--font-geist-sans);color:#000000;}#mermaid-diagram-r24sm .cluster-label text{fill:#333;}#mermaid-diagram-r24sm .cluster-label span{color:#333;}#mermaid-diagram-r24sm .cluster-label span p{background-color:transparent;}#mermaid-diagram-r24sm .label text,#mermaid-diagram-r24sm span{fill:#000000;color:#000000;}#mermaid-diagram-r24sm .node rect,#mermaid-diagram-r24sm .node circle,#mermaid-diagram-r24sm .node ellipse,#mermaid-diagram-r24sm .node polygon,#mermaid-diagram-r24sm .node path{fill:#eee;stroke:#999;stroke-width:1px;}#mermaid-diagram-r24sm .rough-node .label text,#mermaid-diagram-r24sm .node .label text{text-anchor:middle;}#mermaid-diagram-r24sm .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#mermaid-diagram-r24sm .node .label{text-align:center;}#mermaid-diagram-r24sm .node.clickable{cursor:pointer;}#mermaid-diagram-r24sm .arrowheadPath{fill:#333333;}#mermaid-diagram-r24sm .edgePath .path{stroke:#666;stroke-width:2.0px;}#mermaid-diagram-r24sm .flowchart-link{stroke:#666;fill:none;}#mermaid-diagram-r24sm .edgeLabel{background-color:white;text-align:center;}#mermaid-diagram-r24sm .edgeLabel p{background-color:white;}#mermaid-diagram-r24sm .edgeLabel rect{opacity:0.5;background-color:white;fill:white;}#mermaid-diagram-r24sm .labelBkg{background-color:rgba(255, 255, 255, 0.5);}#mermaid-diagram-r24sm .cluster rect{fill:hsl(0, 0%, 98.9215686275%);stroke:#707070;stroke-width:1px;}#mermaid-diagram-r24sm .cluster text{fill:#333;}#mermaid-diagram-r24sm .cluster span{color:#333;}#mermaid-diagram-r24sm div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:var(--font-geist-sans);font-size:12px;background:hsl(-160, 0%, 93.3333333333%);border:1px solid #707070;border-radius:2px;pointer-events:none;z-index:100;}#mermaid-diagram-r24sm .flowchartTitleText{text-anchor:middle;font-size:18px;fill:#000000;}#mermaid-diagram-r24sm .flowchart-link{stroke:hsl(var(--gray-400));stroke-width:1px;}#mermaid-diagram-r24sm .marker,#mermaid-diagram-r24sm marker,#mermaid-diagram-r24sm marker *{fill:hsl(var(--gray-400))!important;stroke:hsl(var(--gray-400))!important;}#mermaid-diagram-r24sm .label,#mermaid-diagram-r24sm text,#mermaid-diagram-r24sm text>tspan{fill:hsl(var(--black))!important;color:hsl(var(--black))!important;}#mermaid-diagram-r24sm .background,#mermaid-diagram-r24sm rect.relationshipLabelBox{fill:hsl(var(--white))!important;}#mermaid-diagram-r24sm .entityBox,#mermaid-diagram-r24sm .attributeBoxEven{fill:hsl(var(--gray-150))!important;}#mermaid-diagram-r24sm .attributeBoxOdd{fill:hsl(var(--white))!important;}#mermaid-diagram-r24sm .label-container,#mermaid-diagram-r24sm rect.actor{fill:hsl(var(--white))!important;stroke:hsl(var(--gray-400))!important;}#mermaid-diagram-r24sm line{stroke:hsl(var(--gray-400))!important;}#mermaid-diagram-r24sm :root{--mermaid-font-family:var(--font-geist-sans);}Submit FormCreate UserSuccessSubmit CredentialsValidSet CookieInvalidRequest FilesQueryReturn FilesUpload FileSubmitEncryptStoreSuccessDownload FileAttributes Satisfy PolicyReturn FileAccess DeniedLogoutUser RegistrationServer ValidationDatabaseLogin PageAuthenticationCreate SessionDashboardFile RetrievalFile Upload FormFile ProcessingCP-ABE EncryptionAccess CheckDecrypt FileError MessageEnd Session
```

## Installation and Setup

### Prerequisites

- Node.js v18.0.0 or newer
- npm or yarn


### Installation Steps

1. Clone the repository:


```shellscript
git clone <repository-url>
cd cp-abe-file-sharing
```

2. Install dependencies:


```shellscript
npm install
```

3. Start the development server:


```shellscript
npm run dev
```

4. Open your browser and navigate to `http://localhost:3000`


### Production Deployment

1. Build the application:


```shellscript
npm run build
```

2. Start the production server:


```shellscript
npm start
```

## Troubleshooting

### Common Issues

1. **Node.js Version**:

1. **Issue**: "SyntaxError: Unexpected token" or other syntax errors
2. **Solution**: Ensure you're using Node.js v18.0.0 or newer
3. **Check**: Run `node -v` to verify your Node.js version



2. **Dependencies**:

1. **Issue**: "Cannot find module" errors
2. **Solution**: Make sure all dependencies are installed
3. **Fix**: Run `npm install` to install missing dependencies



3. **Port Conflicts**:

1. **Issue**: "Port 3000 is already in use"
2. **Solution**: Close other applications using port 3000 or use a different port
3. **Alternative**: Run `npm run dev -- -p 3001` to use port 3001



4. **TypeScript Errors**:

1. **Issue**: TypeScript compilation errors
2. **Solution**: Check the error message and fix the type issues
3. **Tip**: Use proper type annotations for all variables and functions



5. **API Routes**:

1. **Issue**: "API resolved without sending a response"
2. **Solution**: Ensure all API routes return a response
3. **Check**: Verify that all API routes have proper error handling





---

This README provides a comprehensive guide to understanding the CP-ABE Secure File Sharing System. For further assistance or to report issues, please contact the project maintainers.
