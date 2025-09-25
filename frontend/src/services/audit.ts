import type { AuditResult } from '../types/audit'

export async function submitProject(file: File, apiKey?: string, apiBase?: string) {
    const formData = new FormData();
    formData.append('project', file);
    if (apiKey) formData.append('api_key', apiKey);
    if (apiBase) formData.append('api_base', apiBase);

    try {
        const response = await fetch('/api/audit/project', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || error.detail || '项目分析失败');
        }

        const result = (await response.json()) as AuditResult;
        
        if (!result || typeof result !== 'object' || !('status' in result)) {
            throw new Error('无效的响应数据');
        }

        if (!('suspicious_files' in result) || !Array.isArray(result.suspicious_files)) {
            throw new Error('响应数据格式错误');
        }

        return result;
    } catch (error) {
        if (error instanceof Error) {
            throw new Error(`审计失败: ${error.message}`);
        }
        throw new Error('审计失败: 未知错误');
    }
} 