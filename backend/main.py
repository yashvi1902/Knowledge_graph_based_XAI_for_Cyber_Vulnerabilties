from graphbuilder import build_knowledge_graph
from fastapi import FastAPI
from routes import cves  # adjust import as needed

app = FastAPI()

app.include_router(cves.router)

if __name__ == "__main__":
    print("Starting Knowledge Graph creation...")
    build_knowledge_graph()