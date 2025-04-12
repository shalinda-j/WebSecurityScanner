/**
 * Chart generator module for the Web Application Penetration Testing Toolkit
 * Uses Chart.js to create various visualizations for vulnerability data
 */

/**
 * Create a doughnut chart
 * @param {string} canvasId - Canvas element ID
 * @param {string} title - Chart title
 * @param {object} data - Chart data object
 */
function createDoughnutChart(canvasId, title, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                },
                title: {
                    display: true,
                    text: title
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

/**
 * Create a bar chart
 * @param {string} canvasId - Canvas element ID
 * @param {string} title - Chart title
 * @param {object} data - Chart data object
 */
function createBarChart(canvasId, title, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false,
                },
                title: {
                    display: true,
                    text: title
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

/**
 * Create a line chart for trend visualization
 * @param {string} canvasId - Canvas element ID
 * @param {string} title - Chart title
 * @param {object} data - Chart data object
 */
function createLineChart(canvasId, title, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'line',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: title
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

/**
 * Create a radar chart for vulnerability coverage
 * @param {string} canvasId - Canvas element ID
 * @param {string} title - Chart title
 * @param {object} data - Chart data object
 */
function createRadarChart(canvasId, title, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'radar',
        data: data,
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: title
                }
            },
            scales: {
                r: {
                    angleLines: {
                        display: true
                    },
                    suggestedMin: 0
                }
            }
        }
    });
}

/**
 * Create a horizontal bar chart for comparison
 * @param {string} canvasId - Canvas element ID
 * @param {string} title - Chart title
 * @param {object} data - Chart data object
 */
function createHorizontalBarChart(canvasId, title, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: title
                }
            }
        }
    });
}

/**
 * Create a table from vulnerability data
 * @param {string} tableId - Table element ID
 * @param {Array} vulnerabilities - List of vulnerability objects
 */
function createVulnerabilityTable(tableId, vulnerabilities) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    // Clear existing table content
    table.innerHTML = '';
    
    // Create header
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    
    ['Type', 'Severity', 'Location', 'Description', 'Actions'].forEach(headerText => {
        const th = document.createElement('th');
        th.textContent = headerText;
        headerRow.appendChild(th);
    });
    
    thead.appendChild(headerRow);
    table.appendChild(thead);
    
    // Create body
    const tbody = document.createElement('tbody');
    
    vulnerabilities.forEach(vuln => {
        const row = document.createElement('tr');
        
        // Type column
        const typeCell = document.createElement('td');
        typeCell.textContent = vuln.type;
        row.appendChild(typeCell);
        
        // Severity column
        const severityCell = document.createElement('td');
        const severityBadge = document.createElement('span');
        severityBadge.className = 'badge bg-' + getSeverityColor(vuln.severity);
        severityBadge.textContent = vuln.severity;
        severityCell.appendChild(severityBadge);
        row.appendChild(severityCell);
        
        // Location column
        const locationCell = document.createElement('td');
        locationCell.textContent = vuln.location;
        row.appendChild(locationCell);
        
        // Description column
        const descCell = document.createElement('td');
        descCell.textContent = vuln.description;
        row.appendChild(descCell);
        
        // Actions column
        const actionsCell = document.createElement('td');
        const detailsButton = document.createElement('button');
        detailsButton.className = 'btn btn-sm btn-info';
        detailsButton.textContent = 'Details';
        detailsButton.onclick = function() {
            // Show vulnerability details in a modal or accordion
            // Implementation depends on UI structure
        };
        actionsCell.appendChild(detailsButton);
        row.appendChild(actionsCell);
        
        tbody.appendChild(row);
    });
    
    table.appendChild(tbody);
}

/**
 * Get the appropriate Bootstrap color class for a severity level
 * @param {string} severity - Severity level
 * @returns {string} Bootstrap color class
 */
function getSeverityColor(severity) {
    switch (severity) {
        case 'Critical':
            return 'danger';
        case 'High':
            return 'warning';
        case 'Medium':
            return 'info';
        case 'Low':
            return 'success';
        default:
            return 'secondary';
    }
}
