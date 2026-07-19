const API_BASE = 'http://localhost:8000';

export const useScanApi = () => {

  const scanImage = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE}/scan/image`, {
      method: 'POST',
      body: formData,
      // No Content-Type header — fetch sets multipart boundary automatically
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Server error' }));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }
    return await response.json();
  };

  const scanText = async (text) => {
    const response = await fetch(`${API_BASE}/scan/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Server error' }));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }
    return await response.json();
  };

  return { scanImage, scanText };
};
