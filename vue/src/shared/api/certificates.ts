import type {
  GeneratedLocalCertificateRequest,
  LocalCertificateDraft,
  LocalCertificateItem,
  LocalCertificateRemoteBindRequest,
  LocalCertificatesResponse,
  SafeLineCertificateMatchPreviewResponse,
  SafeLineCertificatesPullResponse,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest } from './core'

export function fetchLocalCertificates() {
  return apiRequest<LocalCertificatesResponse>('/certificates/local')
}

export function pullSafeLineCertificates() {
  return apiRequest<SafeLineCertificatesPullResponse>(
    '/integrations/safeline/pull/certificates',
    {
      method: 'POST',
    },
  )
}

export function pullSafeLineCertificate(remoteCertId: string) {
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/pull/certificates/${encodeURIComponent(remoteCertId)}`,
    {
      method: 'POST',
    },
  )
}

export function fetchLocalCertificate(id: number) {
  return apiRequest<LocalCertificateItem>(`/certificates/local/${id}`)
}

export function createLocalCertificate(payload: LocalCertificateDraft) {
  return apiRequest<LocalCertificateItem>('/certificates/local', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function generateLocalCertificate(
  payload: GeneratedLocalCertificateRequest,
) {
  return apiRequest<LocalCertificateItem>('/certificates/local/generate', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateLocalCertificate(
  id: number,
  payload: LocalCertificateDraft,
) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteLocalCertificate(id: number) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: 'DELETE',
  })
}

export function bindLocalCertificateRemote(
  id: number,
  payload: LocalCertificateRemoteBindRequest,
) {
  return apiRequest<WriteStatusResponse>(
    `/certificates/local/${id}/remote-binding`,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
  )
}

export function unbindLocalCertificateRemote(id: number) {
  return apiRequest<WriteStatusResponse>(
    `/certificates/local/${id}/remote-binding`,
    {
      method: 'DELETE',
    },
  )
}

export function pushSafeLineCertificate(localCertificateId: number) {
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/push/certificates/${localCertificateId}`,
    {
      method: 'POST',
    },
  )
}

export function previewSafeLineCertificateMatch(localCertificateId: number) {
  return apiRequest<SafeLineCertificateMatchPreviewResponse>(
    `/integrations/safeline/match/certificates/${localCertificateId}`,
    {
      method: 'POST',
    },
  )
}
