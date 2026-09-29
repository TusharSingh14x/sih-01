"""Evidence batch commitments."""
from alembic import op
from app.models import EvidenceBatch
revision = "0003_batches"
down_revision = "0002_registry"
branch_labels = depends_on = None

def upgrade():
    EvidenceBatch.__table__.create(op.get_bind(), checkfirst=True)

def downgrade():
    raise RuntimeError("Evidence commitments must not be destructively downgraded")
