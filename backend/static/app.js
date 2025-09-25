async function uploadProject() {
    const fileInput = document.getElementById('projectFile');
    const file = fileInput.files[0];
    if (!file) {
        alert('请选择项目文件');
        return;
    }

    const formData = new FormData();
    formData.append('project', file);

    try {
        const response = await fetch('/api/audit/project', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        displayResults(result);
    } catch (error) {
        console.error('审计失败:', error);
        alert('审计过程中发生错误');
    }
}

async function uploadSingleFile() {
    const fileInput = document.getElementById('singleFile');
    const file = fileInput.files[0];
    if (!file) {
        alert('请选择文件');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    try {
        const response = await fetch('/api/audit', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        displayResults(result);
    } catch (error) {
        console.error('审计失败:', error);
        alert('审计过程中发生错误');
    }
}

function displayResults(result) {
    const resultsDiv = document.getElementById('results');
    if (!resultsDiv) return;

    const summary = result.summary || {};
    const suspicious = result.suspicious_files || [];

    const html = `
    <div class="audit-summary ${summary.risk_level || ''}">
      <ul>
        <li>状态: ${result.status || ''}</li>
        <li>发现可疑文件数: ${summary.suspicious_files ?? suspicious.length ?? 0}</li>
        <li>总问题数: ${summary.total_issues ?? 0}</li>
        <li>风险等级: ${(summary.risk_level || 'UNKNOWN').toUpperCase()}</li>
      </ul>
    </div>
    <div class="audit-details">
      ${suspicious.map(f => `
        <div class="file-block">
          <h4>${f.file_path}</h4>
          <pre>${JSON.stringify(f.issues || [], null, 2)}</pre>
        </div>
      `).join('')}
    </div>`;

    resultsDiv.innerHTML = html;
} 