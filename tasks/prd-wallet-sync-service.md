# Product Requirements Document: Wallet Sync Service

## Introduction/Overview

The Wallet Sync Service is a remote API service that allows Tari wallet users to securely upload their view key and receive a fully synchronized wallet database in return. This service addresses the problem of slow initial wallet synchronization and high bandwidth usage by leveraging a cached, high-performance local copy of blockchain data on the server side. Users can upload their view key, wait for processing, then download a compressed, fully synced wallet database.

## Goals

1. **Reduce Initial Sync Time**: Eliminate the need for users to perform lengthy blockchain scanning on their devices
2. **Minimize Bandwidth Usage**: Users download only the final compressed database instead of processing the entire blockchain
3. **Improve User Experience**: Provide a simple API-driven service accessible to general public users
4. **Ensure Security**: Handle view keys securely with encryption and automatic deletion
5. **Optimize Performance**: Process wallet generation as quickly as possible using cached blockchain data

## User Stories

1. **As a new Tari wallet user**, I want to quickly sync my wallet without waiting hours for blockchain scanning, so that I can start using my wallet immediately.

2. **As an existing wallet user switching devices**, I want to restore my wallet state quickly on a new device, so that I don't have to re-sync from scratch.

3. **As a mobile wallet user with limited bandwidth**, I want to avoid downloading large amounts of blockchain data, so that I can sync my wallet without consuming excessive mobile data.

4. **As a user concerned about privacy**, I want assurance that my view key is handled securely and deleted after processing, so that my wallet privacy is maintained.

5. **As a developer integrating this service**, I want clear API endpoints and status notifications, so that I can build a smooth user experience in my application.

## Functional Requirements

1. **View Key Upload**: The system must provide an API endpoint to accept encrypted view keys from users.

2. **Secure Key Handling**: The system must encrypt view keys during transmission and storage, and automatically delete them after wallet database generation is complete.

3. **Blockchain Scanning**: The system must use the existing `scanner.rs` functionality to generate a complete wallet database using the provided view key.

4. **Status Tracking**: The system must provide mechanisms for users to check processing status via polling, push notifications, or WebSocket connections.

5. **Database Compression**: The system must compress the generated wallet database using the most efficient compression algorithm available.

6. **Download Service**: The system must provide a secure download endpoint for users to retrieve their compressed wallet database.

7. **Temporary Storage**: The system must store generated databases for a configurable time period (defined by environment variable) before automatic cleanup.

8. **Rate Limiting**: The system must enforce configurable limits on how frequently users can request wallet generation.

9. **Error Handling**: The system must provide clear error messages for failed processing, invalid view keys, or service unavailability.

10. **API Documentation**: The system must provide comprehensive API documentation for integration by wallet developers.

## Non-Goals (Out of Scope)

1. **Multi-blockchain Support**: This service will only support Tari blockchain, not other cryptocurrencies
2. **Spend Key Handling**: The service will not accept or process spend keys for security reasons
3. **Persistent User Accounts**: No user registration or persistent account management
4. **Real-time Synchronization**: Not a continuous sync service, only one-time database generation
5. **Client-side Wallet Software**: This is purely a backend service, not a wallet application
6. **Blockchain Data Storage**: The service uses existing cached data, not responsible for blockchain node operation

## Design Considerations

- **API Design**: RESTful API with clear endpoints for upload, status checking, and download
- **Security**: HTTPS required, view key encryption, secure temporary storage
- **Scalability**: Design to handle multiple concurrent requests with queue management
- **Monitoring**: Include logging and metrics for processing times and success rates
- **Error Recovery**: Implement retry mechanisms for failed processing attempts

## Technical Considerations

- **Integration**: Must integrate with existing `scanner.rs` binary functionality
- **Database Format**: Output should be compatible with existing Tari wallet database schema
- **Compression**: Evaluate gzip, brotli, or lz4 for optimal compression ratio vs speed
- **Storage**: Temporary file storage with automatic cleanup mechanisms
- **Authentication**: Consider API key or token-based authentication for service access
- **Infrastructure**: Requires high-performance server with SSD storage for cached blockchain data

## Success Metrics

1. **Processing Time**: Average time from view key upload to database ready for download (target: < 30 seconds)
2. **Compression Ratio**: Achieved compression ratio of final database (target: > 70% size reduction)
3. **Success Rate**: Percentage of successful wallet generation requests (target: > 99%)
4. **Error Rate**: Percentage of failed requests due to service issues (target: < 1%)
5. **User Satisfaction**: Measured through reduced support tickets related to sync issues

## API Endpoints (Preliminary)

```
POST /api/v1/wallet/sync
GET /api/v1/wallet/sync/{job_id}/status  
GET /api/v1/wallet/sync/{job_id}/download
DELETE /api/v1/wallet/sync/{job_id}
```

## Open Questions

1. **Authentication Method**: What authentication mechanism should be used for API access?
2. **Notification System**: Which notification method should be prioritized (polling, push, WebSocket)?
3. **Caching Strategy**: How frequently should the cached blockchain data be updated?
4. **Resource Limits**: What are the maximum concurrent processing jobs the service should handle?
5. **Monitoring**: What specific metrics and alerts should be implemented for service health?
6. **Backup Strategy**: How should generated databases be backed up during the retention period?
7. **Geographic Distribution**: Should the service be deployed in multiple regions for performance?

## Implementation Priority

**Phase 1 (MVP)**:
- Basic API endpoints for upload/download
- View key encryption and deletion
- Integration with scanner.rs
- Basic compression and temporary storage

**Phase 2 (Enhanced)**:
- WebSocket notifications
- Advanced rate limiting
- Comprehensive monitoring
- Performance optimizations

**Phase 3 (Advanced)**:
- Multi-region deployment
- Advanced caching strategies
- Detailed analytics and reporting
