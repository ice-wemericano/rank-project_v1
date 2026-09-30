document.getElementById("testBtn").addEventListener("click", async () => {
    const response = await fetch("/api/test");
    const data = await response.json();

    console.log(data);
    alert(data.message);
});