from flask import Flask, render_template_string

app = Flask(__name__)

resume_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Adir Ozeri - Data Analyst</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #000;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .header p {
            margin: 5px 0;
            color: #666;
        }
        .section {
            margin-bottom: 20px;
        }
        .section-title {
            border-bottom: 1px solid #ccc;
            padding-bottom: 5px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .job {
            margin-bottom: 15px;
        }
        .job-header {
            display: flex;
            justify-content: space-between;
        }
        .skills {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .skill {
            background-color: #f0f0f0;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        .download-btn {
            display: block;
            width: 200px;
            margin: 20px auto;
            padding: 10px;
            background-color: #4CAF50;
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }
        .download-btn:hover {
            background-color: #45a049;
        }
        @media print {
            body {
                font-size: 10pt;
            }
            .download-btn {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Adir Ozeri</h1>
        <p>Data Analyst</p>
        <p>Tel Aviv, Israel | +972-050-7757088 | adirozeri@gmail.com</p>
    </div>

    <div class="section">
        <div class="section-title">Professional Summary</div>
        <p>Naturally curious and passionate data analyst with a love for data, statistics, and diving deep into complex problems. Expertise in Python, SQL, and Power BI, with a proven track record of developing dashboards, conducting A/B testing, and providing actionable insights into customer behavior and marketing strategies.</p>
    </div>

    <div class="section">
        <div class="section-title">Professional Experience</div>
        <div class="job">
            <div class="job-header">
                <strong>Data Analyst - Payoneer</strong>
                <span>2023</span>
            </div>
            <ul>
                <li>Conducted marketing campaign analysis to evaluate customer retention and engagement</li>
                <li>Executed A/B tests and interpreted results to optimize marketing strategies</li>
                <li>Developed interactive dashboards and reports using Power BI</li>
                <li>Generated actionable insights through data trends and customer behavior analysis</li>
            </ul>
        </div>

        <div class="job">
            <div class="job-header">
                <strong>Data Analyst - Outbrain</strong>
                <span>2021 - 2022</span>
            </div>
            <ul>
                <li>Enhanced dashboards and automated reports with Python</li>
                <li>Developed operational dashboards and conducted ad-hoc analysis</li>
                <li>Collaborated with cross-functional teams and data warehouses</li>
                <li>Transitioned operational dashboards to scheduled reporting system</li>
            </ul>
        </div>

        <div class="job">
            <div class="job-header">
                <strong>Application Engineer - OptimalPlus</strong>
                <span>2017 - 2020</span>
            </div>
            <ul>
                <li>Performed in-depth troubleshooting and database analysis</li>
                <li>Designed automated testing tools and simulations</li>
                <li>Provided support to engineering and data science teams</li>
                <li>Managed deployment and migration processes</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Skills</div>
        <div class="skills">
            <span class="skill">SQL</span>
            <span class="skill">Python</span>
            <span class="skill">Pandas</span>
            <span class="skill">Numpy</span>
            <span class="skill">Power BI</span>
            <span class="skill">Tableau</span>
            <span class="skill">Machine Learning</span>
            <span class="skill">A/B Testing</span>
            <span class="skill">Statistical Analysis</span>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Education</div>
        <strong>Bachelor's in Mathematics</strong>
        <p>Ben-Gurion University of the Negev (2008 - 2012)</p>
    </div>

    <div class="section">
        <div class="section-title">Certifications</div>
        <ul>
            <li>Applied Machine Learning in Python (Coursera)</li>
            <li>Python for Data Science (Coursera)</li>
            <li>R Programming (Coursera)</li>
        </ul>
    </div>

    <a href="#" class="download-btn" onclick="window.print(); return false;">Download PDF</a>

    <script>
        // Optional: Add print dialog hint
        window.onafterprint = function() {
            alert("To save as PDF, choose 'Save as PDF' in your print dialog.");
        }
    </script>
</body>
</html>
'''


@app.route('/')
def resume():
    return render_template_string(resume_html)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
