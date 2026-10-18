/**
 * Service layer barrel export.
 * UI components should import API/business-logic calls from here
 * (or the individual service modules) instead of embedding fetch
 * calls directly — separation of concerns.
 */
export * from './apiClient';
export * from './ApiError';
export * from './authService';
export * from './invitationService';
