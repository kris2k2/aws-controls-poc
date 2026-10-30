/**
 * Governance guardrails for CDK apps deployed through the AWS CI bootstrap
 * (templates/aws/github-ci-bootstrap.yaml). Copy into the project and call
 * applyProjectGovernance(app, PROJECT) after creating the stacks.
 *
 * - Stacks deploy with the CI role's own credentials (no cdk-* bootstrap
 *   roles), run CloudFormation as the bootstrap's execution role, and publish
 *   assets to the bootstrap's asset bucket / ECR repository.
 * - Every IAM role, managed policy and instance profile, including the ones
 *   CDK creates internally for custom resources, gets the project's path and
 *   permissions boundary.
 * - Stack names must be PROJECT or PROJECT-*; anything else fails synth.
 *
 * See standards/security/aws-ci-bootstrap.md.
 */
import {
  Annotations, App, Aspects, CfnResource, CliCredentialsStackSynthesizer, Fn, IAspect, Stack, StackProps,
} from "aws-cdk-lib";
import { IConstruct } from "constructs";

/** Canadian data residency first; us-east-1 only for what must live there (e.g. CloudFront certificates). */
export const DEFAULT_REGION = "ca-central-1";
export const ALTERNATE_REGION = "us-east-1";

const IAM_TYPES = new Set(["AWS::IAM::Role", "AWS::IAM::ManagedPolicy", "AWS::IAM::InstanceProfile"]);

export function projectSynthesizer(project: string): CliCredentialsStackSynthesizer {
  return new CliCredentialsStackSynthesizer({
    fileAssetsBucketName: `${project}-assets-\${AWS::AccountId}-\${AWS::Region}`,
    imageAssetsRepositoryName: `${project}-assets`,
    cloudFormationExecutionRole: `arn:\${AWS::Partition}:iam::\${AWS::AccountId}:role/bootstrap/${project}-cfn-exec`,
  });
}

/** Stack props with the governed synthesizer and the default Canadian region. */
export function projectStackProps(project: string, props: StackProps = {}): StackProps {
  return {
    ...props,
    synthesizer: projectSynthesizer(project),
    env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: DEFAULT_REGION, ...props.env },
  };
}

class ProjectGuardrails implements IAspect {
  constructor(private readonly project: string) {}

  visit(node: IConstruct): void {
    if (node instanceof Stack) {
      const name = node.stackName;
      if (name !== this.project && !name.startsWith(`${this.project}-`)) {
        Annotations.of(node).addError(`Stack name '${name}' must be '${this.project}' or start with '${this.project}-'.`);
      }
      return;
    }
    if (!(node instanceof CfnResource) || !IAM_TYPES.has(node.cfnResourceType)) {
      return;
    }
    node.addPropertyOverride("Path", `/${this.project}/`);
    if (node.cfnResourceType === "AWS::IAM::Role") {
      node.addPropertyOverride(
        "PermissionsBoundary",
        Fn.sub(`arn:\${AWS::Partition}:iam::\${AWS::AccountId}:policy/bootstrap/${this.project}-ci-boundary`),
      );
    }
  }
}

export function applyProjectGovernance(app: App, project: string): void {
  Aspects.of(app).add(new ProjectGuardrails(project));
}
