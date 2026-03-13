// Utility functions for the Cyber Threat Detection Dashboard

// IP address validation
export const isValidIPv4 = (ip: string): boolean => {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
};

// Port validation
export const isValidPort = (port: number): boolean => {
  return port >= 0 && port <= 65535;
};

// Format date/time
export const formatDateTime = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

// Format confidence score as percentage
export const formatConfidence = (confidence: number): string => {
  return `${(confidence * 100).toFixed(1)}%`;
};

// Download file helper
export const downloadFile = (content: string, filename: string, mimeType: string = 'text/csv') => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

// Parse CSV file
export const parseCSV = (content: string): string[][] => {
  const lines = content.trim().split('\n');
  return lines.map(line => line.split(',').map(cell => cell.trim()));
};

// Validate CSV structure
export const validateCSVStructure = (rows: string[][]): { valid: boolean; error?: string } => {
  if (rows.length < 2) {
    return { valid: false, error: 'CSV must contain at least a header row and one data row' };
  }

  const headers = rows[0];
  const requiredHeaders = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'packet_size', 'duration'];
  
  const hasAllHeaders = requiredHeaders.every(header => 
    headers.some(h => h.toLowerCase() === header.toLowerCase())
  );

  // if (!hasAllHeaders) {
  //   return { 
  //     valid: false, 
  //     error: `CSV must contain the following columns: ${requiredHeaders.join(', ')}` 
  //   };
  // }

  return { valid: true };
};

// Get severity color
export const getSeverityColor = (severity?: 'High' | 'Medium' | 'Low'): string => {
  switch (severity) {
    case 'High': return 'text-red-400';
    case 'Medium': return 'text-yellow-400';
    case 'Low': return 'text-blue-400';
    default: return 'text-gray-400';
  }
};

// Get prediction color
export const getPredictionColor = (prediction: 'Normal' | 'Malicious'): string => {
  return prediction === 'Malicious' ? 'text-red-400' : 'text-green-400';
};

// Sanitize input to prevent XSS
export const sanitizeInput = (input: string): string => {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
};

// Debounce function
export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
<<<<<<< HEAD
  let timeout: ReturnType<typeof setTimeout>;
=======
  let timeout: NodeJS.Timeout;
>>>>>>> 260c5da33751fd3b387bc26d584989d6a0489685
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

// Generate sample CSV data
export const generateSampleCSV = (): string => {
  const headers = 'source_ip,destination_ip,source_port,destination_port,protocol,packet_size,duration';
  const rows = [
    '192.168.1.100,10.0.0.50,8080,443,TCP,1024,5.2',
    '172.16.0.5,8.8.8.8,53,53,UDP,512,0.1',
    '192.168.1.101,10.0.0.51,3389,3389,TCP,2048,15.7',
    '10.10.10.10,192.168.1.1,12345,80,TCP,1500,3.5',
    '172.16.0.10,172.16.0.20,1024,1025,TCP,256,1.2'
  ];
  
  return [headers, ...rows].join('\n');
};
