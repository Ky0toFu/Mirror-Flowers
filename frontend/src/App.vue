<template>
  <div class="container">
    <h1>AI代码审计工具</h1>
    
    <!-- API配置部分 -->
    <div class="config-section">
      <h2>API配置</h2>
      <div class="form-group">
        <input 
          type="text" 
          v-model="apiKey" 
          placeholder="OpenAI API Key"
        >
        <input 
          type="text" 
          v-model="apiBase" 
          placeholder="API Base URL（可选）"
        >
        <button @click="updateConfig">更新配置</button>
      </div>
    </div>
    
    <div class="upload-section">
      <input 
        type="file" 
        @change="handleFileUpload" 
        accept=".php,.java,.py,.js"
      >
      <button @click="startAudit" :disabled="!selectedFile">开始审计</button>
    </div>
    
    <div class="results-section" v-if="auditResults">
      <h2>审计结果</h2>
      <div v-if="'suspicious_files' in auditResults">
        <div class="analysis-card">
          <h3>摘要</h3>
          <ul>
            <li>状态: {{ auditResults.status }}</li>
            <li>可疑文件数: {{ auditResults.summary?.suspicious_files ?? 0 }}</li>
            <li>总问题数: {{ auditResults.summary?.total_issues ?? 0 }}</li>
            <li>风险等级: {{ auditResults.summary?.risk_level ?? 'unknown' }}</li>
          </ul>
        </div>
        <div
          v-for="file in auditResults.suspicious_files"
          :key="file.file_path"
          class="analysis-card"
        >
          <h3>{{ file.file_path }}</h3>
          <pre>{{ JSON.stringify(file.issues, null, 2) }}</pre>
        </div>
      </div>
      <div v-else>
        <pre>{{ JSON.stringify(auditResults, null, 2) }}</pre>
      </div>
    </div>
    
    <div class="loading" v-if="loading">
      分析中...
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue'
import { submitProject } from './services/audit'
import type { SingleFileAuditResult, ProjectAuditResult } from './types/audit'

 type AuditView = SingleFileAuditResult | ProjectAuditResult | null

 export default defineComponent({
   data() {
     return {
       selectedFile: null as File | null,
       auditResults: null as AuditView,
       loading: false,
       apiKey: '',
       apiBase: '',
       fileLanguage: null as string | null
     }
   },
   methods: {
    async updateConfig() {
      try {
        const response = await fetch('/api/configure', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            api_key: this.apiKey,
            api_base: this.apiBase || undefined
          })
        });
        
        if (response.ok) {
          window.alert('API配置已更新');
        } else {
          throw new Error('配置更新失败');
        }
      } catch (error) {
        console.error('配置更新失败:', error);
        window.alert('配置更新失败');
      }
    },
    
    handleFileUpload(event) {
      const file = event.target.files[0];
      const supportedTypes = {
        '.php': 'PHP',
        '.java': 'Java',
        '.py': 'Python',
        '.js': 'JavaScript'
      };
      
      const fileExt = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
      if (!supportedTypes[fileExt]) {
        window.alert('不支持的文件类型。支持的文件类型包括: .php, .java, .py, .js');
        return;
      }
      
      this.selectedFile = file;
      this.fileLanguage = supportedTypes[fileExt];
    },
    
    async startAudit() {
      if (!this.selectedFile) return
      
      this.loading = true
      
      try {
        const formData = new FormData()
        formData.append('file', this.selectedFile)
        if (this.apiKey) {
          formData.append('api_key', this.apiKey)
        }
        if (this.apiBase) {
          formData.append('api_base', this.apiBase)
        }

        const response = await fetch('/api/audit', {
          method: 'POST',
          body: formData
        })

        if (!response.ok) {
          const errorBody = await response.json()
          throw new Error(errorBody.detail || '审计请求失败')
        }

        const result = (await response.json())
        this.auditResults = result
      } catch (error) {
        console.error('审计失败:', error)
        window.alert(`审计过程中发生错误: ${error instanceof Error ? error.message : '未知错误'}`)
      } finally {
        this.loading = false
      }
    }
  }
}
</script>

<style scoped>
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.config-section {
  margin: 20px 0;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
}

.form-group {
  display: flex;
  gap: 10px;
  margin: 10px 0;
}

input[type="text"] {
  flex: 1;
  padding: 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.upload-section {
  margin: 20px 0;
}

.analysis-card {
  background: #f5f5f5;
  padding: 20px;
  margin: 10px 0;
  border-radius: 8px;
}

.loading {
  text-align: center;
  margin: 20px 0;
  font-size: 18px;
}
</style> 