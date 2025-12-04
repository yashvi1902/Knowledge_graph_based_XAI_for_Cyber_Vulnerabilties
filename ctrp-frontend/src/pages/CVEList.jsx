import { useEffect, useState } from "react";
import { Link } from "react-router-dom";  
import { fetchCVEList } from "../apis/client";

export default function CVEList() {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchCVEList().then((res) => {
            setData(res.results);
        })
        .catch((err) => {
            console.error("Error fetching CVEs:", err);
            setError("Failed to load CVEs from backend");
        })
        .finally(() => setLoading(false));
      }, []);

    if (loading) return <p>Loading...</p>;
    if (error) return <p style={{ color: "red" }}>{error}</p>;

    return (
        <div>
            <h1>CVE Explorer</h1>
            <table border="1">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        {/* <th>Published</th> */}
                        <th>Status</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                    {data.map((item) => (
                        <tr key={item.cve_id}>
                            <td>
                                {/* Clickable link to detail page */}
                                <Link to={`/cve/${item.cve_id}`}>
                                    {item.cve_id}
                                </Link>
                            </td>
                            {/* <td>{item.published}</td> */}
                            <td>{item.status}</td>
                            <td>{item.source}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
