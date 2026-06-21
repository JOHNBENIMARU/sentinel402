/// Generate dynamic SVG badge for Sentinel402 audit reports
pub fn generate_badge(risk_score: &str) -> String {
    let (color, label) = match risk_score.to_uppercase().as_str() {
        "CATASTROPHE" => ("#e05d44", "CATASTROPHE"),
        "DISASTER" => ("#fe7d37", "DISASTER"),
        "CALAMITY" => ("#dfb317", "CALAMITY"),
        "HAZARD" => ("#97ca00", "HAZARD"),
        "SAFE" => ("#4c1", "SAFE"),
        _ => ("#9f9f9f", "UNKNOWN"),
    };

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20">
    <linearGradient id="b" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <mask id="a">
        <rect width="160" height="20" rx="3" fill="#fff"/>
    </mask>
    <g mask="url(#a)">
        <path fill="#555" d="M0 0h90v20H0z"/>
        <path fill="{color}" d="M90 0h70v20H90z"/>
        <path fill="url(#b)" d="M0 0h160v20H0z"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
        <text x="45" y="15" fill="#010101" fill-opacity=".3">Sentinel402</text>
        <text x="45" y="14">Sentinel402</text>
        <text x="125" y="15" fill="#010101" fill-opacity=".3">{label}</text>
        <text x="125" y="14">{label}</text>
    </g>
</svg>"##,
        color = color,
        label = label
    )
}
